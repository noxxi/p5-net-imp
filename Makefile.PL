use ExtUtils::MakeMaker;
require 5.10.0;
WriteMakefile(
    NAME => 'Net::IMP',
    VERSION_FROM => 'lib/Net/IMP.pm',
    LICENSE => 'perl',
    PREREQ_PM => {
    },
    META_MERGE => {
	resources => {
	    repository => 'https://github.com/noxxi/p5-net-imp',
	},
   },
);

