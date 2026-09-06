import pathlib, unittest
ROOT=pathlib.Path(__file__).resolve().parents[3]
class HILReleaseMatrix(unittest.TestCase):
    def test_all_release_boards_are_hil_selectable(self):
        runner=(ROOT/'qa/checks/firmware/run_hardware_tests.py').read_text()
        cli=(ROOT/'qa/linux/run-all.sh').read_text()
        self.assertIn('"waveshare-af"', runner)
        self.assertIn('feature = "ov5640-af" if board == "waveshare-af" else board', runner)
        self.assertIn('waveshare|waveshare-af|m5stack', cli)
if __name__=='__main__': unittest.main()
