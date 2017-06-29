import logging as logger


class DatasetAuthorizationList(object):
    @classmethod
    def from_stream(cls, file_obj):
        data = file_obj.read()
        return cls.from_string(data)
    
    @classmethod
    def get_object_from_gcs(cls, bucket_name, object_name):
        from google_helpers.storage_service import get_storage_resource
        storage_service = get_storage_resource()
        req = storage_service.objects().get_media(bucket=bucket_name,
                                                  object=object_name)
        file_contents = req.execute()
        return file_contents
    
    @classmethod
    def from_google_cloud_storage(cls, bucket_name, object_name):
        file_contents = cls.get_object_from_gcs(bucket_name, object_name)
        
        return cls.from_string(file_contents)
