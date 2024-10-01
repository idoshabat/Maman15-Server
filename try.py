import uuid
generated_uuid = str(uuid.uuid4()).replace("-", "")[:16]
print(generated_uuid)
print(len(str(generated_uuid)))