# S3 Buckets

Use this when the files a partner uploads and collects live in AWS S3, or in
anything that speaks its API — MinIO, Ceph, Backblaze B2, Cloudflare R2. The
proxy signs its own requests, so no gateway is needed in front of the bucket.

## Enable the s3 backend

By default, support for `s3://` URLs is not enabled. You must include an 
`s3Backend` section in the configuration to make the `s3` scheme available.

You do not need to configure any buckets in the `s3Backend` section; they 
can be provided dynamically per entry.

```json
{
  "$schema": "./schemas/sftp-proxy.schema.json",
  "hostKeyFile": "/config/host_key",
  "s3Backend": {
    "buckets": [
      {
        "bucket": "acme-archive",
        "region": "us-east-1",
        "accessKeyId": "AKIAEXAMPLE",
        "secretAccessKey": "wJalrXUtnFEMIexamplekey"
      }
    ]
  },
  "users": [
    {
      "username": "acme",
      "passwordHash": "$2a$12$CftPk3E1S3CJ4lnPavA1/.fw.FTIn4jwgHd13aqZ693MMJEvFUmT.",
      "rootfs": {
        "children": [
          {
            "directory": "Inbound",
            "backend": "s3://acme-archive/inbound"
          },
          {
            "directory": "Outbound",
            "backend": "s3://acme-archive/outbound",
            "allowedMethods": ["ListObjectsV2", "GetObject"]
          }
        ]
      }
    }
  ]
}
```

The example hash is for the password `password`; generate your own with
`docker run --rm -it sftp-proxy -hash-password`.

You can limit the operations by setting the `allowedMethods` field on a 
directory or file node.  The default is allow all.  Valid options are:

- `ListObjectsV2`
- `GetObject`
- `PutObject`
- `DeleteObject`
- `CopyObject`

## S3-Compatible Stores

Specify `endpoint` to direct requests to an S3-compatible store rather than AWS.

```json
"s3Backend": {
  "buckets": [
    {
      "bucket": "acme-archive",
      "region": "us-east-1",
      "endpoint": "http://minio:9000",
      "accessKeyId": "minioadmin",
      "secretAccessKey": "minioadmin"
    }
  ]
}
```

## Default Credentials

By default, ambient credentials are not used.  If you are running the proxy on
on EC2, ECS, or EKS, you can access buckets without access keys and secrets
by using the `useDefaultCredentials` option.

```json
{ "bucket": "acme-archive", "region": "us-east-1", "useDefaultCredentials": true }
```

## Explicit Credentials

Either in the config or in a response from an HTTP back-end, you can provide 
provide explicit credentials for that particular node.  No `s3Backend.buckets`
entry is required when the directory's `s3` property is specified.

```json
{
  "directory": "Archive",
  "backend": "s3://tenant-42-archive/2026",
  "s3": {
    "region": "us-east-1",
    "accessKeyId": "ASIAEXAMPLE",
    "secretAccessKey": "wJalrXUtnFEMIexamplekey",
    "sessionToken": "IQoJb3JpZ2luX2VjE..."
  }
}
```

## Object Provenance

Every object uploaded through the proxy is stored with user metadata naming who
sent it. By default:

```
x-amz-meta-user-agent: sftp-proxy
x-amz-meta-user-agent-id: acme
```

These are the same two keys AWS Transfer Family writes, so a Lambda or an S3
event consumer written against Transfer Family reads them unchanged.

You can set custom metadata for each object by providing a `headers` object on the 
user. This replaces the default headers rather than adding to them. For example:

```json
{
  "username": "acme",
  "passwordHash": "$2a$12$...",
  "headers": {
    "user-agent-id": "acme@sftp.example.com",
    "tenant": "42"
  },
  "rootfs": { "backend": "s3://acme-archive/" }
}
```

## Limitations

- Listing a container prefix of more than 10,000 entries will only return the first 10,000.
- Uploading files larger than 5 GiB are not supported.
- Directories are virtual and cannot be created or removed explicitly.
