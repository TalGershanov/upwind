from logic import known_domains


def test_parses_domains_and_skips_comments(tmp_path):
    path = tmp_path / 'top.txt'
    path.write_text('# Tranco top 2\n\nAmazon.DE\n  google.com  \n',
                    encoding='utf-8')
    assert known_domains.load_top_domains(str(path)) == {
        'amazon.de', 'google.com'}


def test_missing_file_gives_empty_set(tmp_path, caplog):
    domains = known_domains.load_top_domains(str(tmp_path / 'missing.txt'))
    assert domains == frozenset()
    assert 'could not be read' in caplog.text


def test_bundled_list_has_the_big_brands():
    domains = known_domains.load_top_domains()
    assert {'amazon.com', 'amazon.de', 'google.com'} <= domains
