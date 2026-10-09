"""Rustfmt must not alter the source-model graph or permit empty arguments."""
import unittest
from model import split_args

class GenericArguments(unittest.TestCase):
    def test_multiline_trailing_comma(self):
        self.assertEqual(split_args("g::Send<A, B, M>,\n g::Roll<X>,\n"),
                         ["g::Send<A, B, M>", "g::Roll<X>"])

    def test_nested_trailing_comma_stays_in_nested_type(self):
        self.assertEqual(split_args("g::Seq<A, B,>, C,"), ["g::Seq<A, B,>", "C"])

    def test_empty_inner_argument_is_rejected(self):
        with self.assertRaises(ValueError):
            split_args("A,,B")
        with self.assertRaises(ValueError):
            split_args(",A")

    def test_single_argument_and_empty_list(self):
        self.assertEqual(split_args("A,"), ["A"])
        self.assertEqual(split_args(""), [])

if __name__ == "__main__":
    unittest.main()
