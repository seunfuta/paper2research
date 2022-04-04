-- SQLite
select * from block_hashes inner join files
where (block_hashes.md5 != 'bf619eac0cdf3f68d496ea9344137e8b') and (block_hashes.md5 !=  'de03fe65a6765caa8c91343acc62cffc')