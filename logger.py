import sqlite3


class Logger():

    def __init__(self, database_path):
        self.database_path = database_path
        conn = sqlite3.connect(database_path)
        cursor = conn.cursor()
        cursor.execute(
            '''create table if not exists requests (
            request_id text,
            authorization text,
            content_length text,
            date text,
            host text,
            x_amz_content_sha256 text,
            x_amz_date text,
            x_amz_glacier_version text,
            x_amz_sha256_tree_hash text,
            request_headers text
            )'''
        )
        conn.commit()
        conn.close()



if __name__ == '__main__':
    logger = Logger('example.db')