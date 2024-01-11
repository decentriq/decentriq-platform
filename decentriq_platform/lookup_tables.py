from .types import MatchingId, MatchingIdFormat, TableColumnHashingAlgorithm

# Map the user specified matching ID to the corresponding internal
# matching ID format and hashing algorithm.
MATCHING_ID_INTERNAL_LOOKUP = {
    MatchingId.STRING: (MatchingIdFormat.STRING, None),
    MatchingId.EMAIL: (MatchingIdFormat.EMAIL, None),
    MatchingId.HASHED_EMAIL: (
        MatchingIdFormat.EMAIL,
        TableColumnHashingAlgorithm.SHA256_HEX,
    ),
    MatchingId.PHONE_NUMBER: (MatchingIdFormat.PHONE_NUMBER_E164, None),
    MatchingId.HASHED_PHONE_NUMBER: (
        MatchingIdFormat.PHONE_NUMBER_E164,
        TableColumnHashingAlgorithm.SHA256_HEX,
    ),
}