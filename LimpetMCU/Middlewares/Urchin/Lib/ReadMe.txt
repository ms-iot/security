========================================================================
    STATIC LIBRARY : Urchin Library
========================================================================

This library was derived from the TPM 2.0 library reference implementation turned
inside out. The thought was that the TPM has all code to marshal/unmarshal all data
structures, properly calculate authorizations, perform parameter encryption and do
auditing and it has to be possible to take this functionality as a library that can
be used on the client. Using the TPM defined functions for all this means that all
this functionality is spec compliant, because it is taken from the specification.

This code is by no means optimized for either memory footprint or execution performance.
Arguably it is not even pretty, but - and can't stress this enough - it really works well.