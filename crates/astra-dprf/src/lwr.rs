//! LWR-based exact-coalition DPRF profile.
//!
//! This implementation follows the concrete arithmetic profile of Sinha,
//! Patranabis, and Mukhopadhyay: n=1024, q=2^64, q1=2^42, and p=2^10.
//! It is restricted to static, semi-honest, exact coalitions. ML-DSA evidence
//! authenticates a partial but does not prove that the partial was computed
//! correctly, so this backend makes no malicious-robustness claim.

use crate::{
    ClausePolicy, DprfBackend, DprfError, EvaluationRequest, PartialEvaluation, validate_and_select,
};
use astra_common::Secret32;
use getrandom::fill;
use shake::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// LWR key-vector dimension from the concrete paper profile.
pub const LWR_DIMENSION: usize = 1024;
/// Number of bits in each partial evaluation modulo q1.
pub const PARTIAL_BITS: u32 = 42;
/// Number of bits in one base LWR PRF output modulo p.
pub const OUTPUT_BITS: usize = 10;
/// Parallel base-PRF instances required to extract 256 output bits.
pub const PARALLEL_INSTANCES: usize = 26;

const TOTAL_WORDS: usize = LWR_DIMENSION * PARALLEL_INSTANCES;
const PARTIAL_BYTES: usize = PARALLEL_INSTANCES * 8;
const Q1_MASK: u64 = (1_u64 << PARTIAL_BITS) - 1;
const P_MASK: u64 = (1_u64 << OUTPUT_BITS) - 1;
const HASH_TO_VECTOR_LABEL: &[u8] = b"ASTRA-PQ-LWR-H2V-v1";
const PROVISIONING_MAGIC: &[u8; 8] = b"ASTRALW1";
const PROVISIONING_CHECKSUM_LABEL: &[u8] = b"ASTRA-PQ-LWR-PROVISIONING-v1";
const PROVISIONING_CHECKSUM_BYTES: usize = 32;

/// Public description of the concrete experimental parameter set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LwrParameters {
    /// LWR vector dimension.
    pub dimension: usize,
    /// Logarithm of the input modulus q.
    pub log_q: u32,
    /// Logarithm of the partial modulus q1.
    pub log_q1: u32,
    /// Logarithm of the base output modulus p.
    pub log_p: usize,
    /// Number of parallel base instances.
    pub parallel_instances: usize,
    /// Final output size in bits.
    pub extracted_output_bits: usize,
}

/// One authority's secret vector for one exact clause coalition.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LwrExactCoalitionShare {
    authority_id: String,
    clause_id: String,
    epoch: u64,
    share_version: u64,
    coalition: Vec<String>,
    words: Vec<u64>,
}

impl fmt::Debug for LwrExactCoalitionShare {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LwrExactCoalitionShare")
            .field("authority_id", &self.authority_id)
            .field("clause_id", &self.clause_id)
            .field("epoch", &self.epoch)
            .field("share_version", &self.share_version)
            .field("coalition_size", &self.coalition.len())
            .field("secret_words", &"[REDACTED]")
            .finish()
    }
}

impl LwrExactCoalitionShare {
    /// Returns the authority identifier without exposing secret words.
    #[must_use]
    pub fn authority_id(&self) -> &str {
        &self.authority_id
    }

    /// Returns the governance clause and coalition identifier bound to this share.
    #[must_use]
    pub fn clause_id(&self) -> &str {
        &self.clause_id
    }

    /// Returns the number of protected key bytes held by this authority.
    #[must_use]
    pub const fn secret_size_bytes(&self) -> usize {
        TOTAL_WORDS * 8
    }

    /// Returns the sorted exact coalition bound to this share.
    #[must_use]
    pub fn coalition(&self) -> &[String] {
        &self.coalition
    }

    /// Encodes this secret share for controlled offline lab provisioning.
    ///
    /// The returned buffer is zeroized on drop and includes corruption
    /// detection, but it is not encrypted or authenticated. It must be
    /// transferred over an authenticated administrative channel and stored in
    /// a file readable only by the authority account.
    pub fn export_lab_provisioning(&self) -> Result<Zeroizing<Vec<u8>>, DprfError> {
        let coalition_count = u16::try_from(self.coalition.len())
            .map_err(|_| backend_error("coalition count does not fit provisioning format"))?;
        let word_count = u32::try_from(self.words.len())
            .map_err(|_| backend_error("word count does not fit provisioning format"))?;
        let mut encoded = Zeroizing::new(Vec::with_capacity(
            TOTAL_WORDS * 8 + self.coalition.len() * 32 + 256,
        ));
        encoded.extend_from_slice(PROVISIONING_MAGIC);
        encode_text(&mut encoded, &self.authority_id)?;
        encode_text(&mut encoded, &self.clause_id)?;
        encoded.extend_from_slice(&self.epoch.to_be_bytes());
        encoded.extend_from_slice(&self.share_version.to_be_bytes());
        encoded.extend_from_slice(&coalition_count.to_be_bytes());
        for authority in &self.coalition {
            encode_text(&mut encoded, authority)?;
        }
        encoded.extend_from_slice(&word_count.to_be_bytes());
        for word in &self.words {
            encoded.extend_from_slice(&word.to_be_bytes());
        }
        let checksum = provisioning_checksum(&encoded);
        encoded.extend_from_slice(&checksum);
        Ok(encoded)
    }

    /// Decodes a secret share delivered through the controlled lab
    /// provisioning channel.
    pub fn import_lab_provisioning(encoded: &[u8]) -> Result<Self, DprfError> {
        if encoded.len() <= PROVISIONING_CHECKSUM_BYTES {
            return Err(backend_error("truncated LWR provisioning object"));
        }
        let payload_length = encoded.len() - PROVISIONING_CHECKSUM_BYTES;
        let (payload, supplied_checksum) = encoded.split_at(payload_length);
        let expected_checksum = provisioning_checksum(payload);
        if !constant_time_equal(supplied_checksum, &expected_checksum) {
            return Err(backend_error("LWR provisioning checksum mismatch"));
        }

        let mut reader = ProvisioningReader::new(payload);
        if reader.read_exact(PROVISIONING_MAGIC.len())? != PROVISIONING_MAGIC {
            return Err(backend_error("invalid LWR provisioning format"));
        }
        let authority_id = reader.read_text()?;
        let clause_id = reader.read_text()?;
        let epoch = reader.read_u64()?;
        let share_version = reader.read_u64()?;
        let coalition_count = usize::from(reader.read_u16()?);
        if !(1..=32).contains(&coalition_count) {
            return Err(backend_error("invalid provisioned coalition size"));
        }
        let coalition = (0..coalition_count)
            .map(|_| reader.read_text())
            .collect::<Result<Vec<_>, _>>()?;
        let word_count = reader.read_u32()?;
        if word_count != TOTAL_WORDS as u32 {
            return Err(backend_error("unexpected provisioned LWR word count"));
        }
        let words = (0..TOTAL_WORDS)
            .map(|_| reader.read_u64())
            .collect::<Result<Vec<_>, _>>()?;
        if !reader.is_empty() {
            return Err(backend_error("trailing LWR provisioning data"));
        }
        validate_setup(&clause_id, epoch, share_version, &coalition)?;
        if coalition.windows(2).any(|pair| pair[0] >= pair[1])
            || coalition.binary_search(&authority_id).is_err()
        {
            return Err(backend_error("invalid provisioned coalition membership"));
        }
        Ok(Self {
            authority_id,
            clause_id,
            epoch,
            share_version,
            coalition,
            words,
        })
    }
}

struct ProvisioningReader<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> ProvisioningReader<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn read_exact(&mut self, length: usize) -> Result<&'a [u8], DprfError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| backend_error("provisioning length overflow"))?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or_else(|| backend_error("truncated LWR provisioning object"))?;
        self.offset = end;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, DprfError> {
        let bytes: [u8; 2] = self
            .read_exact(2)?
            .try_into()
            .map_err(|_| backend_error("invalid provisioned u16"))?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u32(&mut self) -> Result<u32, DprfError> {
        let bytes: [u8; 4] = self
            .read_exact(4)?
            .try_into()
            .map_err(|_| backend_error("invalid provisioned u32"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, DprfError> {
        let bytes: [u8; 8] = self
            .read_exact(8)?
            .try_into()
            .map_err(|_| backend_error("invalid provisioned u64"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_text(&mut self) -> Result<String, DprfError> {
        let length = usize::from(self.read_u16()?);
        if length == 0 || length > 256 {
            return Err(backend_error("invalid provisioned text length"));
        }
        let bytes = self.read_exact(length)?;
        let value = std::str::from_utf8(bytes)
            .map_err(|_| backend_error("provisioned text is not UTF-8"))?;
        if value.chars().any(char::is_control) {
            return Err(backend_error(
                "provisioned text contains control characters",
            ));
        }
        Ok(value.to_owned())
    }

    const fn is_empty(&self) -> bool {
        self.offset == self.encoded.len()
    }
}

fn encode_text(encoded: &mut Vec<u8>, value: &str) -> Result<(), DprfError> {
    let length = u16::try_from(value.len())
        .map_err(|_| backend_error("text does not fit provisioning format"))?;
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(backend_error("invalid provisioning text"));
    }
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(value.as_bytes());
    Ok(())
}

fn provisioning_checksum(encoded: &[u8]) -> [u8; PROVISIONING_CHECKSUM_BYTES] {
    let mut hasher = Shake256::default();
    hasher.update(PROVISIONING_CHECKSUM_LABEL);
    hasher.update(encoded);
    let mut reader = hasher.finalize_xof();
    let mut checksum = [0_u8; PROVISIONING_CHECKSUM_BYTES];
    reader.read(&mut checksum);
    checksum
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left_byte, right_byte)| {
            difference | (left_byte ^ right_byte)
        })
        == 0
}

/// Static semi-honest LWR backend for one exact coalition per clause key.
#[derive(Clone, Copy, Debug, Default)]
pub struct LwrExactCoalitionBackend;

impl LwrExactCoalitionBackend {
    /// Returns the concrete non-secret parameter description.
    #[must_use]
    pub const fn parameters() -> LwrParameters {
        LwrParameters {
            dimension: LWR_DIMENSION,
            log_q: 64,
            log_q1: PARTIAL_BITS,
            log_p: OUTPUT_BITS,
            parallel_instances: PARALLEL_INSTANCES,
            extracted_output_bits: 256,
        }
    }

    /// Returns the exact adversarial profile supported by this backend.
    #[must_use]
    pub const fn security_profile() -> &'static str {
        "post-quantum LWR; static corruption; semi-honest; exact coalition"
    }
}

/// Generates additive exact-coalition shares using operating-system randomness.
///
/// The lexicographically first authority is the leader with reconstruction
/// coefficient +1. Every other authority has coefficient -1. The unshared key
/// is erased before this function returns.
pub fn setup_exact_coalition(
    clause_id: &str,
    epoch: u64,
    share_version: u64,
    authority_ids: &[String],
) -> Result<BTreeMap<String, LwrExactCoalitionShare>, DprfError> {
    validate_setup(clause_id, epoch, share_version, authority_ids)?;
    let mut coalition = authority_ids.to_vec();
    coalition.sort();

    let mut key = random_words()?;
    let mut share_words = Vec::with_capacity(coalition.len());
    share_words.push(key.clone());
    for _ in 1..coalition.len() {
        let random_share = random_words()?;
        for (leader_word, random_word) in key.iter_mut().zip(&random_share) {
            *leader_word = leader_word.wrapping_add(*random_word);
        }
        share_words.push(random_share);
    }
    share_words[0].copy_from_slice(&key);
    key.zeroize();

    let shares = coalition
        .iter()
        .cloned()
        .zip(share_words)
        .map(|(authority_id, words)| {
            let share = LwrExactCoalitionShare {
                authority_id: authority_id.clone(),
                clause_id: clause_id.to_owned(),
                epoch,
                share_version,
                coalition: coalition.clone(),
                words,
            };
            (authority_id, share)
        })
        .collect();
    Ok(shares)
}

impl DprfBackend for LwrExactCoalitionBackend {
    type Share = LwrExactCoalitionShare;

    fn backend_id(&self) -> &'static str {
        "lwr-n1024-q64-q1-42-p10-x26-static-semi-honest"
    }

    fn partial_evaluate(
        &self,
        authority_id: &str,
        share: &Self::Share,
        request: &EvaluationRequest,
    ) -> Result<PartialEvaluation, DprfError> {
        request.validate()?;
        if authority_id != share.authority_id
            || request.clause_id != share.clause_id
            || request.epoch != share.epoch
            || request.share_version != share.share_version
            || share.words.len() != TOTAL_WORDS
        {
            return Err(backend_error("share metadata does not match the request"));
        }

        let input_vector = hash_to_vector(request);
        let mut payload = Vec::with_capacity(PARTIAL_BYTES);
        for instance in 0..PARALLEL_INSTANCES {
            let start = instance * LWR_DIMENSION;
            let instance_share = &share.words[start..start + LWR_DIMENSION];
            let inner_product = input_vector.iter().zip(instance_share).fold(
                0_u64,
                |accumulator, (input, secret)| {
                    accumulator.wrapping_add(input.wrapping_mul(*secret))
                },
            );
            let rounded = round_q_to_q1(inner_product);
            payload.extend_from_slice(&rounded.to_le_bytes());
        }

        Ok(PartialEvaluation {
            authority_id: authority_id.to_owned(),
            clause_id: request.clause_id.clone(),
            epoch: request.epoch,
            share_version: request.share_version,
            input: request.input,
            payload,
            proof: Vec::new(),
        })
    }

    fn combine(
        &self,
        policy: &ClausePolicy,
        request: &EvaluationRequest,
        partials: &[PartialEvaluation],
    ) -> Result<Secret32, DprfError> {
        if policy.members.len() != usize::from(policy.threshold) {
            return Err(backend_error(
                "LWR profile requires an exact coalition whose size equals the threshold",
            ));
        }
        let selected = validate_and_select(policy, request, partials)?;
        let leader = selected
            .partials()
            .first()
            .ok_or_else(|| backend_error("empty selected coalition"))?
            .authority_id
            .as_str();

        let mut base_outputs = [0_u16; PARALLEL_INSTANCES];
        for (instance, base_output) in base_outputs.iter_mut().enumerate() {
            let mut accumulator = 0_u64;
            for partial in selected.partials() {
                if partial.payload.len() != PARTIAL_BYTES || !partial.proof.is_empty() {
                    return Err(backend_error("invalid LWR partial encoding"));
                }
                let offset = instance * 8;
                let encoded: [u8; 8] = partial.payload[offset..offset + 8]
                    .try_into()
                    .map_err(|_| backend_error("invalid LWR partial encoding"))?;
                let value = u64::from_le_bytes(encoded);
                if value > Q1_MASK {
                    return Err(backend_error("LWR partial is outside Z_q1"));
                }
                accumulator = if partial.authority_id == leader {
                    accumulator.wrapping_add(value)
                } else {
                    accumulator.wrapping_sub(value)
                } & Q1_MASK;
            }
            *base_output = round_q1_to_p(accumulator) as u16;
        }
        Ok(Secret32::from_bytes(pack_256_bits(&base_outputs)))
    }
}

fn validate_setup(
    clause_id: &str,
    epoch: u64,
    share_version: u64,
    authority_ids: &[String],
) -> Result<(), DprfError> {
    if clause_id.is_empty()
        || clause_id.len() > 256
        || clause_id.chars().any(char::is_control)
        || epoch == 0
        || share_version == 0
        || authority_ids.is_empty()
        || authority_ids.len() > 32
    {
        return Err(backend_error("invalid exact-coalition setup"));
    }
    let unique: BTreeSet<&str> = authority_ids.iter().map(String::as_str).collect();
    if unique.len() != authority_ids.len()
        || unique
            .iter()
            .any(|identifier| identifier.is_empty() || identifier.len() > 256)
    {
        return Err(backend_error("invalid or duplicate authority identifier"));
    }
    Ok(())
}

fn random_words() -> Result<Vec<u64>, DprfError> {
    let mut bytes = vec![0_u8; TOTAL_WORDS * 8];
    fill(&mut bytes).map_err(|error| backend_error(format!("OS randomness failed: {error}")))?;
    let words = bytes
        .chunks_exact(8)
        .map(|chunk| {
            let encoded: [u8; 8] = chunk.try_into().expect("chunk length is fixed");
            u64::from_le_bytes(encoded)
        })
        .collect();
    bytes.zeroize();
    Ok(words)
}

fn hash_to_vector(request: &EvaluationRequest) -> Vec<u64> {
    let mut hasher = Shake256::default();
    hasher.update(HASH_TO_VECTOR_LABEL);
    hasher.update(&(request.clause_id.len() as u64).to_be_bytes());
    hasher.update(request.clause_id.as_bytes());
    hasher.update(&request.epoch.to_be_bytes());
    hasher.update(&request.share_version.to_be_bytes());
    hasher.update(request.input.as_bytes());
    let mut reader = hasher.finalize_xof();
    let mut bytes = vec![0_u8; LWR_DIMENSION * 8];
    reader.read(&mut bytes);
    bytes
        .chunks_exact(8)
        .map(|chunk| {
            let encoded: [u8; 8] = chunk.try_into().expect("chunk length is fixed");
            u64::from_le_bytes(encoded)
        })
        .collect()
}

const fn round_q_to_q1(value: u64) -> u64 {
    let shift = 64 - PARTIAL_BITS;
    let rounding = 1_u64 << (shift - 1);
    value.wrapping_add(rounding).wrapping_shr(shift) & Q1_MASK
}

const fn round_q1_to_p(value: u64) -> u64 {
    let shift = PARTIAL_BITS - OUTPUT_BITS as u32;
    let rounding = 1_u64 << (shift - 1);
    value.wrapping_add(rounding).wrapping_shr(shift) & P_MASK
}

#[cfg(test)]
const fn round_q_to_p(value: u64) -> u64 {
    let shift = 64 - OUTPUT_BITS as u32;
    let rounding = 1_u64 << (shift - 1);
    value.wrapping_add(rounding).wrapping_shr(shift) & P_MASK
}

fn pack_256_bits(outputs: &[u16; PARALLEL_INSTANCES]) -> [u8; 32] {
    let mut packed = [0_u8; 32];
    let mut output_bit = 0_usize;
    for value in outputs {
        for source_bit in 0..OUTPUT_BITS {
            if output_bit == 256 {
                return packed;
            }
            if (value >> source_bit) & 1 == 1 {
                packed[output_bit / 8] |= 1 << (output_bit % 8);
            }
            output_bit += 1;
        }
    }
    packed
}

fn backend_error(message: impl Into<String>) -> DprfError {
    DprfError::Backend(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use astra_common::Digest32;

    fn policy(authorities: &[String]) -> ClausePolicy {
        ClausePolicy {
            clause_id: "risk-floor:coalition-1".to_owned(),
            threshold: authorities.len() as u16,
            members: authorities
                .iter()
                .enumerate()
                .map(|(index, authority)| (authority.clone(), format!("organization-{index}")))
                .collect(),
            require_distinct_organizations: true,
        }
    }

    fn request(marker: u8) -> EvaluationRequest {
        EvaluationRequest {
            clause_id: "risk-floor:coalition-1".to_owned(),
            epoch: 7,
            share_version: 2,
            input: Digest32::from_bytes([marker; 32]),
        }
    }

    #[test]
    fn exact_five_authority_coalition_is_deterministic() {
        let authorities: Vec<String> = (1..=5).map(|index| format!("a{index}")).collect();
        let shares = setup_exact_coalition("risk-floor:coalition-1", 7, 2, &authorities).unwrap();
        let backend = LwrExactCoalitionBackend;
        let request = request(9);
        let partials: Vec<PartialEvaluation> = authorities
            .iter()
            .map(|authority| {
                backend
                    .partial_evaluate(authority, &shares[authority], &request)
                    .unwrap()
            })
            .collect();
        let first = backend
            .combine(&policy(&authorities), &request, &partials)
            .unwrap();
        let second = backend
            .combine(&policy(&authorities), &request, &partials)
            .unwrap();
        assert_eq!(first.expose_secret(), second.expose_secret());
        assert_ne!(first.expose_secret(), &[0; 32]);

        let mut reconstructed_key = shares[&authorities[0]].words.clone();
        for authority in &authorities[1..] {
            for (key_word, share_word) in reconstructed_key.iter_mut().zip(&shares[authority].words)
            {
                *key_word = key_word.wrapping_sub(*share_word);
            }
        }
        let input_vector = hash_to_vector(&request);
        let mut direct_outputs = [0_u16; PARALLEL_INSTANCES];
        for (instance, output) in direct_outputs.iter_mut().enumerate() {
            let start = instance * LWR_DIMENSION;
            let inner_product = input_vector
                .iter()
                .zip(&reconstructed_key[start..start + LWR_DIMENSION])
                .fold(0_u64, |accumulator, (input, secret)| {
                    accumulator.wrapping_add(input.wrapping_mul(*secret))
                });
            *output = round_q_to_p(inner_product) as u16;
        }
        let direct = pack_256_bits(&direct_outputs);
        reconstructed_key.zeroize();
        assert_eq!(first.expose_secret(), &direct);
    }

    #[test]
    fn lab_provisioning_round_trip_preserves_share() {
        let authorities: Vec<String> = (1..=3).map(|index| format!("a{index}")).collect();
        let shares = setup_exact_coalition("risk-floor:coalition-1", 7, 2, &authorities).unwrap();
        let original = &shares["a2"];
        let encoded = original.export_lab_provisioning().unwrap();
        let imported = LwrExactCoalitionShare::import_lab_provisioning(&encoded).unwrap();
        assert_eq!(imported.authority_id, original.authority_id);
        assert_eq!(imported.clause_id, original.clause_id);
        assert_eq!(imported.epoch, original.epoch);
        assert_eq!(imported.share_version, original.share_version);
        assert_eq!(imported.coalition, original.coalition);
        assert_eq!(imported.words, original.words);
    }

    #[test]
    fn corrupted_lab_provisioning_is_rejected() {
        let authorities = vec!["a1".to_owned(), "a2".to_owned()];
        let shares = setup_exact_coalition("risk-floor:coalition-1", 7, 2, &authorities).unwrap();
        let mut encoded = shares["a1"].export_lab_provisioning().unwrap();
        encoded[100] ^= 0x80;
        assert!(LwrExactCoalitionShare::import_lab_provisioning(&encoded).is_err());
    }

    #[test]
    fn missing_authority_fails_closed() {
        let authorities: Vec<String> = (1..=3).map(|index| format!("a{index}")).collect();
        let shares = setup_exact_coalition("risk-floor:coalition-1", 7, 2, &authorities).unwrap();
        let backend = LwrExactCoalitionBackend;
        let request = request(9);
        let partials: Vec<PartialEvaluation> = authorities[..2]
            .iter()
            .map(|authority| {
                backend
                    .partial_evaluate(authority, &shares[authority], &request)
                    .unwrap()
            })
            .collect();
        assert!(matches!(
            backend.combine(&policy(&authorities), &request, &partials),
            Err(DprfError::ThresholdNotMet {
                required: 3,
                qualifying: 2,
            })
        ));
    }

    #[test]
    fn changed_input_changes_output() {
        let authorities = vec!["a1".to_owned(), "a2".to_owned()];
        let shares = setup_exact_coalition("risk-floor:coalition-1", 7, 2, &authorities).unwrap();
        let backend = LwrExactCoalitionBackend;
        let evaluate = |request: &EvaluationRequest| {
            let partials: Vec<PartialEvaluation> = authorities
                .iter()
                .map(|authority| {
                    backend
                        .partial_evaluate(authority, &shares[authority], request)
                        .unwrap()
                })
                .collect();
            backend
                .combine(&policy(&authorities), request, &partials)
                .unwrap()
        };
        let first = evaluate(&request(9));
        let second = evaluate(&request(10));
        assert_ne!(first.expose_secret(), second.expose_secret());
    }
}
