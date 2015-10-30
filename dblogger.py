# -*- coding: latin-1 -*-

import sqlite3
from settings import GlacierParams
import datetime


def convert_dict_keys_to_alphanum(source_dict):
    return dict(map(
        lambda x: (x[0].lower().replace('-', '_'), x[1]),
        source_dict.items())
    )


class DBLogger():
    def __init__(self, database_path):
        self.database_path = database_path
        self.conn = None
        cursor = self.get_cursor()
        # cursor.execute('''drop table if exists requests''')
        # cursor.execute('''drop table if exists responses''')
        cursor.execute(
            '''create table if not exists requests (
            id integer primary key,
            content_length text,
            date text,
            host text,
            authorization text,
            x_amz_glacier_version text,
            x_amzn_requestid text,
            x_amz_date text,
            x_amz_content_sha256 text,
            x_amz_sha256_tree_hash text,
            headers text
            )'''
        )
        cursor.execute(
            '''create table if not exists responses (
            id integer primary key,
            content_length text,
            content_type text,
            date text,
            x_amzn_requestid text,
            x_amz_sha256_tree_hash text,
            headers text
            )'''
        )
        # Inventory table
        cursor.execute(
            '''create table if not exists inventory (
            id integer primary key,
            vault text,
            file_name text,
            file_size text,
            upload_date text,
            inventory_date text
            )'''
        )

        self.commit_and_close(cursor)

    def get_cursor(self):
        conn = sqlite3.connect(self.database_path)
        return conn.cursor()

    def commit_and_close(self, cursor):
        cursor.connection.commit()
        cursor.connection.close()

    def get_columns(self, table_name):
        cursor = self.get_cursor()
        stmt = cursor.execute("PRAGMA table_info(%s)" % (table_name,))
        return [item[1] for item in stmt.fetchall()]

    def insert(self, table, headers, body, param):
        cursor = self.get_cursor()
        sql_friendly_headers = convert_dict_keys_to_alphanum(headers)
        # add the original headers dictionary to the table
        sql_friendly_headers['headers'] = str(headers)
        # add current timestamp
        sql_friendly_headers['record_date'] = datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S')
        # add target url
        sql_friendly_headers['url'] = param.get(GlacierParams.URI)
        # add request method
        sql_friendly_headers['method'] = param.get(GlacierParams.METHOD)
        # add response body
        sql_friendly_headers['body'] = str(body)
        columns = self.get_columns(table)
        for header in sql_friendly_headers:
            # Add a column for each header
            if header not in columns:
                cursor.execute('ALTER TABLE %s ADD COLUMN %s text' % (table, header))
        # c.execute("PRAGMA table_info(requests)")
        sql_columns = ', '.join(sorted(sql_friendly_headers.keys()))
        placeholders = ':' + ', :'.join(sorted(sql_friendly_headers.keys()))
        query = "INSERT INTO %s (%s) VALUES (%s)" % (table, sql_columns, placeholders)
        # print(query)
        # query = r"""INSERT INTO %s (request_id, date) VALUES (:request-id, :date)""" % (table,)
        # print(query)
        # print(sql_friendly_headers)
        result = cursor.execute(query, sql_friendly_headers)
        # print(result)
        self.commit_and_close(cursor)
        return result

    def insert_request(self, headers, param):
        return self.insert('requests', headers, None, param)

    def insert_response(self, headers, body, param):
        return self.insert('responses', headers, body, param)


if __name__ == '__main__':
    logger = DBLogger('database.db')
    headers = {'authorization': datetime.datetime.today().strftime('%Y-%m-%d %H:%M:%S')}
    logger.insert('requests', headers)
    # print(logger.get_columns('requests'))