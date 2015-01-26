import sqlite3











if __name__=='__main__':
    conn = sqlite3.connect('example.db')
    c = conn.cursor()
    c.execute('''create table req
              (authorization, content_length, date, host, x_amz_content_sha256, x_amz_date, x_amz_glacier_version, x_amz_sha256_tree_hash)''')
    conn.commit()
    conn.close()
