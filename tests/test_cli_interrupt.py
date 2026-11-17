import binproof.cli as cli


def test_ctrl_c_exits_cleanly_with_130(export, monkeypatch, capsys):
    root, _ = export

    def interrupted(analysis, args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_cmd_functions", interrupted)
    assert cli.main(["functions", str(root)]) == 130
    captured = capsys.readouterr()
    assert "interrupted" in captured.err and "Traceback" not in captured.err
