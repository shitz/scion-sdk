// Copyright 2025 Mysten Labs
// Copyright 2025 Anapaya Systems
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Test utilities

/// Shortcut for `<string>.parse().unwrap()`.
macro_rules! parse {
    ($string:literal) => {
        $string.parse().unwrap()
    };
}

pub(crate) use parse;

/// Macro for creating parametrized *synchronous* tests.
///
/// The `param_test!` macro accepts the name of an existing function, followed by a list of case
/// names and their arguments. It expands to a module with a `#[test]` function for each of the
/// cases. Each test case calls the existing, named function with their provided arguments.
///
/// See [`async_param_test`] for a similar macro that works with `async` function.
///
/// # Examples
///
/// Calling a simple test function can be done as follows
///
/// ```
/// # use test_utils::param_test;
/// #
/// param_test! {
///     test_sum: [
///         positive_sums: (10, 7, 17),
///         negative_sums: (-5, -3, -8)
///     ]
/// }
/// fn test_sum(lhs: i32, rhs: i32, sum: i32) {
///     assert_eq!(lhs + rhs, sum);
/// }
/// ```
///
/// Additionally, test functions can also have return types, such as a [`Result`]:
///
/// ```
/// # use std::error::Error;
/// # use test_utils::param_test;
/// #
/// param_test! {
///     test_parses -> Result<(), Box<dyn Error>>: [
///         positive: ("21", 21),
///         negative: ("-17", -17)
///     ]
/// }
/// fn test_parses(to_parse: &str, expected: i32) -> Result<(), Box<dyn Error>> {
///     assert_eq!(expected, to_parse.parse()?);
///     Ok(())
/// }
/// ```
///
/// Finally, attributes such as as `#[ignore]` may be added to individual tests:
///
/// ```
/// # use std::error::Error;
/// # use test_utils::param_test;
/// #
/// param_test! {
///     test_parses -> Result<(), Box<dyn Error>>: [
///         #[ignore] positive: ("21", 21),
///         negative: ("-17", -17)
///     ]
/// }
/// fn test_parses(to_parse: &str, expected: i32) -> Result<(), Box<dyn Error>> {
///     assert_eq!(expected, to_parse.parse()?);
///     Ok(())
/// }
/// ```
macro_rules! param_test {
    ($func_name:ident -> $return_ty:ty: [
        $( $(#[$outer:meta])* $case_name:ident: ( $($args:expr),+ )  ),+$(,)?
    ]) => {
        mod $func_name {
            use super::*;

            $(
                #[test]
                $(#[$outer])*
                fn $case_name() -> $return_ty {
                    $func_name($($args),+)
                }
            )*
        }
    };
    ($func_name:ident: [
        $( $(#[$outer:meta])* $case_name:ident: ( $($args:expr),+ ) ),+$(,)?
    ]) => {
        param_test!($func_name -> (): [ $( $(#[$outer])* $case_name: ( $($args),+ ) ),+ ]);
    };
}

pub(crate) use param_test;

/// Macro for creating parametrized *asynchronous* tests.
///
/// This macro behaves similarly to the [`param_test`] macro, however it must be used with an
/// `async` function. For convenience, the macro expands the test cases with the `#[tokio::test]`
/// attribute. If specifying any additional attributes to any test case, it is necessary to
/// re-specify the `#[tokio::test]` macro for *every* test case.
///
/// See [`param_test`] for more information and examples.
macro_rules! async_param_test {
    ($func_name:ident -> $return_ty:ty: [
        $( $(#[$outer:meta])+ $case_name:ident: ( $($args:expr),+ ) ),+$(,)?
    ]) => {
        mod $func_name {
            use super::*;

            $(
                $(#[$outer])+
                async fn $case_name() -> $return_ty {
                    $func_name($($args),+).await
                }
            )*
        }
    };
    ($func_name:ident: [
        $( $(#[$outer:meta])+ $case_name:ident: ( $($args:expr),+ ) ),+$(,)?
    ]) => {
        async_param_test!( $func_name -> (): [ $( $(#[$outer])+ $case_name: ($($args),+) ),* ] );
    };

    ($func_name:ident: [
        $( $case_name:ident: ( $($args:expr),+ ) ),+$(,)?
    ]) => {
        async_param_test!( $func_name -> (): [ $( #[tokio::test] $case_name: ($($args),+) ),* ] );
    };
    ($func_name:ident -> $return_ty:ty: [
        $( $case_name:ident: ( $($args:expr),+ ) ),+$(,)?
    ]) => {
        async_param_test!(
            $func_name -> $return_ty: [ $( #[tokio::test] $case_name: ( $($args),+ ) ),* ]
        );
    }
}
pub(crate) use async_param_test;

#[cfg(test)]
mod tests {
    use std::error::Error;

    super::param_test! {
        test_with_no_return: [
            case1: (true, 1, 1),
            case2: (false, 3, 4)
        ]
    }
    fn test_with_no_return(bool_arg: bool, usize_arg: usize, u32_arg: u32) {
        assert_eq!(bool_arg, usize_arg == u32_arg as usize);
    }

    super::param_test! {
        test_with_return -> Result<(), Box<dyn Error>>: [
            case1: ("5", 5),
            case2: ("7", 7)
        ]
    }
    fn test_with_return(to_parse: &str, parsed: usize) -> Result<(), Box<dyn Error>> {
        assert_eq!(parsed, to_parse.parse::<usize>()?);
        Ok(())
    }

    super::async_param_test! {
        async_test_with_return -> Result<(), Box<dyn Error>>: [
            case1: ("5", 5),
            case2: ("7", 7)
        ]
    }
    async fn async_test_with_return(to_parse: &str, parsed: usize) -> Result<(), Box<dyn Error>> {
        assert_eq!(parsed, to_parse.parse::<usize>()?);
        Ok(())
    }
}
