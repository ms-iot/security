========================================================================
    STATIC LIBRARY : Urchin Platform library for Windows 8 and above
========================================================================

// Note: This code was derived from the TCG TPM 2.0 Library Specification at
// http://www.trustedcomputinggroup.org/resources/tpm_library_specification

This library provides the necessary platform support for Urchin. It is
implemented using BCrypt for cryptographic primitive and RNG support and the TBS to
get access to the TPM on the platform.

The Urchin library was derived from the TPM 2.0 library reference implementation turned
inside out. The thought was that the TPM has all code to marshal/unmarshal all data
structures, properly calculate authorizations, perform parameter encryption and do
auditing and it has to be possible to take this functionality as a library that can
be used on the client. Using the TPM defined functions for all this means that all
this functionality is spec compliant, because it is taken from the specification.

This code is by no means optimized for either memory footprint or execution performance.
Arguably it is not even pretty, but - and can't stress this enough - it really works well.

