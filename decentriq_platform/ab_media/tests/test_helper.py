from ..helper import flatten_mutable_fields


def test_flatten():
    input = {
        "version": "0.0.1",
        "advertiser_manifest_hash": None,
        "segments_manifest_hash": None,
        "embeddings_manifest_hash": None,
        "demographics_manifest_hash": None,
        "matching_manifest_hash": None,
        "audiences": [
            {
                "id": "overlap-shoes",
                "kind": "advertiser",
                "audience_type": "shoes",
                "audience_size": 2672,
                "mutable": {"name": "All publisher users in shoes", "status": "ready"},
            },
            {
                "id": "overlap-hot tubs",
                "kind": "advertiser",
                "audience_type": "hot tubs",
                "audience_size": 2716,
                "mutable": {
                    "name": "All publisher users in hot tubs",
                    "status": "ready",
                },
            },
            {
                "id": "overlap-insurance",
                "kind": "advertiser",
                "audience_type": "insurance",
                "audience_size": 2673,
                "mutable": {
                    "name": "All publisher users in insurance",
                    "status": "ready",
                },
            },
        ],
    }

    expected_output = {
        "version": "0.0.1",
        "advertiser_manifest_hash": None,
        "segments_manifest_hash": None,
        "embeddings_manifest_hash": None,
        "demographics_manifest_hash": None,
        "matching_manifest_hash": None,
        "audiences": [
            {
                "id": "overlap-shoes",
                "kind": "advertiser",
                "audience_type": "shoes",
                "audience_size": 2672,
                "name": "All publisher users in shoes",
                "status": "ready",
            },
            {
                "id": "overlap-hot tubs",
                "kind": "advertiser",
                "audience_type": "hot tubs",
                "audience_size": 2716,
                "name": "All publisher users in hot tubs",
                "status": "ready",
            },
            {
                "id": "overlap-insurance",
                "kind": "advertiser",
                "audience_type": "insurance",
                "audience_size": 2673,
                "name": "All publisher users in insurance",
                "status": "ready",
            },
        ],
    }

    result = flatten_mutable_fields(input)
    assert result == expected_output
