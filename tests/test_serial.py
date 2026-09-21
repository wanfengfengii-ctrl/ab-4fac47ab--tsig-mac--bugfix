import unittest

from app.serial import SerialRelation, compare, is_forward


class TestSerialArithmetic(unittest.TestCase):
    def test_basic_order(self):
        self.assertEqual(compare(0, 1), SerialRelation.GREATER)
        self.assertEqual(compare(1, 0), SerialRelation.LESS)
        self.assertEqual(compare(5, 5), SerialRelation.EQUAL)

    def test_wraparound(self):
        self.assertEqual(compare(4294967295, 0), SerialRelation.GREATER)
        self.assertEqual(compare(0, 4294967295), SerialRelation.LESS)
        self.assertTrue(is_forward(4294967295, 0)[0])

    def test_undecidable_boundary(self):
        self.assertEqual(compare(0, 2147483648), SerialRelation.UNDECIDABLE)
        self.assertEqual(compare(4294967295, 2147483647),
                         SerialRelation.UNDECIDABLE)
        ok, msg = is_forward(0, 2147483648)
        self.assertFalse(ok)
        self.assertIn("undecidable", msg)

    def test_equal_and_backward_rejected(self):
        self.assertFalse(is_forward(10, 10)[0])
        self.assertFalse(is_forward(10, 9)[0])

    def test_just_inside_half_window(self):
        self.assertEqual(compare(0, 2147483647), SerialRelation.GREATER)
        self.assertEqual(compare(0, 2147483649), SerialRelation.LESS)


if __name__ == "__main__":
    unittest.main()
