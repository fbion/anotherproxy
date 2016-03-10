
from: http://tschottdorf.github.io/linking-golang-go-statically-cgo-testing/

Edit (04/11/2015): Ever since Go 1.4 came around, this article has been slightly outdated. A change in 1.4 altered the behaviour of the -a flag such that it would not rebuild the standard library. Consequently, the netgo tag did not have the desired effect any more. There are various discussions about this to be found online, and luckily there's an easy fix: just add the -installsuffix netgo parameter to your go build flags. That causes the packages to be built in ${GOROOT}/pkg/<arch>_netgo instead, causing the -a flag to behave as it should.
