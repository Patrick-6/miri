#![allow(unused)] // TODO GENMC

use std::pin::Pin;

use cxx::UniquePtr;
use cxx::memory::UniquePtrTarget;

#[repr(transparent)]
pub struct NonNullUniquePtr<T: UniquePtrTarget> {
    inner: UniquePtr<T>,
}

impl<T: UniquePtrTarget> NonNullUniquePtr<T> {
    pub fn new(input: UniquePtr<T>) -> Option<Self> {
        if input.is_null() {
            None
        } else {
            // SAFETY: `input` is not null
            Some(unsafe { Self::new_unchecked(input) })
        }
    }

    pub unsafe fn new_unchecked(input: UniquePtr<T>) -> Self {
        Self { inner: input }
    }

    pub fn into_inner(self) -> UniquePtr<T> {
        self.inner
    }

    pub fn as_mut(&mut self) -> Pin<&mut T> {
        let ptr = self.inner.as_mut_ptr();

        // SAFETY: `inner` is not null (checked at struct creation)
        let mut_reference = unsafe { ptr.as_mut().unwrap_unchecked() };
        // SAFETY: TODO GENMC (should be the same reason as in CXX crate, but there is no safety comment there)
        unsafe { Pin::new_unchecked(mut_reference) }
    }
}
