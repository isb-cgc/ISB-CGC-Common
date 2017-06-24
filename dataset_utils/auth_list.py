import logging as logger


class DatasetAuthorizationList(object):
    @classmethod
    def from_stream(cls, file_obj):
        data = file_obj.read()
        return cls.from_string(data)

    @classmethod
    def from_google_cloud_storage(cls, bucket_name, filename):
        from google_helpers.storage_service import get_storage_resource
        logger.debug("DatasetAuthorizationList.from_google_cloud_storage {} {}".format(repr(bucket_name), repr(filename)))
        storage_service = get_storage_resource()
        req = storage_service.objects().get_media(bucket=bucket_name,
                                                  object=filename)
        file_contents = req.execute()

        return cls.from_string(file_contents)
