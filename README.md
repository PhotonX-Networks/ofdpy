OfdPy
=====
OfdPy is a collection of modules that make working with Broadcoms OFDPA, which
can be found at <https://github.com/Broadcom-Switch/of-dpa>, easier. These
modules were designed by PhotonX Networks for the COSIGN project 
<http://www.fp7-cosign.eu/>. Currently only a small amount of functions
are available, but please feel free to add more functionality, or ask
me to add more. Preferably by opening an Issue with the 'Enhancement'
tag.


Installation
------------
The easiest way to install is to download the OfdPy repository using:

```
git clone https://github.com/PhotonX-Networks/OfdPy.git
```

You can then create your script in the created OfdPy folder. Note that
folder structure is important as per Python imports. Alternatively,
install the module in your python distribution using the `setup.py` 
script, by running:

```
python setup.py install
```


Project structure
-----------------
The `ofdpy` folder contains the source code for the modules. Examples
on how to use these modules can be found in `examples/Ryu` for usage
with the Ryu controller <http://osrg.github.io/ryu/> and in 
`examples/ODL` for usage with an ODL controller <https://www.opendaylight.org/>.
Unit test for the code can be found in `test`, but a non-developer should
not need these.
