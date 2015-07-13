# pyGlacier
Amazon Glacier client library, written in python 3, using Amazon's REST API directly (not the boto library).
The main advantage of this library is that it allows the caller to know the upload progress via a callback mechanism.

Example usage:

1. Set the environmental variable AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to your amazon access key ID and secret respectively

2. Instantiate the client, passing the region as parameter

    client = GlacierClient('us-east-1')

3. Perform one of the following operations:

    3.1 Vaults operations

        3.1.1 List Vaults

            client.list_vaults()

        3.1.2 Describe Vault

            client.describe_vault(vault_name)

    3.2 Job operations

        3.2.1 List jobs for a particular vault

            client.list_jobs(vault_name)

        3.2.2 Describe job (passing the vault name and the id of the job, which you can get using the method 3.2.1)

            client.describe_job(vault_name, job_id)

        3.2.3 Initiate inventory request job (for a valut_name)

            client.initiate_inventory_job(vault_name)

            This will start an inventory request job (which usually takes about 4 hourd to complete) and return the id of the job in case of success.
            You can periodically check if the job ended using the method 3.2.2 with the job id returned by this one.
            After completion, you can collect the job output with the appropriate method.

        3.2.4 Get job output (passing hte vault_name and the job_id)

            client.get_job_output(vault_name, job_id)

            this method wil return a requests.Response object, whose body contains the job output.

    3.3 Archive operations

        3.3.1 Upload a file (with path file_path) in a single upload (not multipart), to the vault vault_name

            client.upload_archive(vault_name, file_path)

        3.3.2 Multipart upload: upload a file in chunks, to minimize the impact of connection errors. The vault used is vault_name,
        the file description is automatically set to the file name, the file path is archive_path. Optionally, one could specify the part size (the size of
        the chunks) in the settings.

            client.multiupload_archive(vault_name, archive_path)
