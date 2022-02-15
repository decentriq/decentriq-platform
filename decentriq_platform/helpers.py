from .proto import CreateDataRoomResponse


def get_data_room_id(create_data_room_response: CreateDataRoomResponse) -> bytes:
    response_type = create_data_room_response.WhichOneof("create_data_room_response")
    if response_type is None:
        raise Exception("Empty CreateDataRoomResponse")
    elif response_type == "dataRoomId":
        return create_data_room_response.dataRoomId
    elif response_type == "dataRoomValidationError":
        raise Exception(
            "DataRoom creation failed",
            create_data_room_response.dataRoomValidationError
        )
    else:
        raise Exception("Unknown response type for CreateDataRoomResponse", response_type)
