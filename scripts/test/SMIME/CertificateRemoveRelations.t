# --
# Copyright (C) 2001-2019 OTRS AG, https://otrs.com/
# --
# This software comes with ABSOLUTELY NO WARRANTY. For details, see
# the enclosed file COPYING for license information (GPL). If you
# did not receive this file, see https://www.gnu.org/licenses/gpl-3.0.txt.
# --

use strict;
use warnings;
use utf8;

use vars (qw($Self));
use File::Path qw(mkpath rmtree);

use Kernel::Output::HTML::ArticleCheck::SMIME;

# get needed objects
my $ConfigObject    = $Kernel::OM->Get('Kernel::Config');
my $MainObject      = $Kernel::OM->Get('Kernel::System::Main');
my $TicketObject    = $Kernel::OM->Get('Kernel::System::Ticket');
my $ArticleObject   = $Kernel::OM->Get('Kernel::System::Ticket::Article');
my $HTMLUtilsObject = $Kernel::OM->Get('Kernel::System::HTMLUtils');

# get helper object
$Kernel::OM->ObjectParamAdd(
    'Kernel::System::UnitTest::Helper' => {
        RestoreDatabase  => 1,
        UseTmpArticleDir => 1,
    },
);
my $Helper = $Kernel::OM->Get('Kernel::System::UnitTest::Helper');

# Disable email addresses checking.
$Helper->ConfigSettingChange(
    Key   => 'CheckEmailAddresses',
    Value => 0,
);

my $HomeDir = $ConfigObject->Get('Home');

# create directory for certificates and private keys
my $CertPath    = $ConfigObject->Get('Home') . "/var/tmp/certs";
my $PrivatePath = $ConfigObject->Get('Home') . "/var/tmp/private";
mkpath( [$CertPath],    0, 0770 );    ## no critic
mkpath( [$PrivatePath], 0, 0770 );    ## no critic

# set SMIME paths
$ConfigObject->Set(
    Key   => 'SMIME::CertPath',
    Value => $CertPath,
);
$ConfigObject->Set(
    Key   => 'SMIME::PrivatePath',
    Value => $PrivatePath,
);

my $OpenSSLBin = $ConfigObject->Get('SMIME::Bin') || '/usr/bin/openssl';

# get the openssl version string, e.g. OpenSSL 0.9.8e 23 Feb 2007
my $OpenSSLVersionString = qx{$OpenSSLBin version};
my $OpenSSLMajorVersion;

# get the openssl major version, e.g. 1 for version 1.0.0
if ( $OpenSSLVersionString =~ m{ \A (?: OpenSSL )? \s* ( \d )  }xmsi ) {
    $OpenSSLMajorVersion = $1;
}

# openssl version 1.0.0 uses different hash algorithm... in the future release of openssl this might
#change again in such case a better version detection will be needed
my $UseNewHashes;
if ( $OpenSSLMajorVersion >= 1 ) {
    $UseNewHashes = 1;
}

# set config
$ConfigObject->Set(
    Key   => 'SMIME',
    Value => 1,
);
$ConfigObject->Set(
    Key   => 'SendmailModule',
    Value => 'Kernel::System::Email::DoNotSendEmail',
);

# check if openssl is located there
if ( !-e $OpenSSLBin ) {

    # maybe it's a mac with macport
    if ( -e '/opt/local/bin/openssl' ) {
        $ConfigObject->Set(
            Key   => 'SMIME::Bin',
            Value => '/opt/local/bin/openssl',
        );
    }
}

# create crypt object
my $SMIMEObject = $Kernel::OM->Get('Kernel::System::Crypt::SMIME');

if ( !$SMIMEObject ) {
    print STDERR "NOTICE: No SMIME support!\n";

    if ( !-e $OpenSSLBin ) {
        $Self->False(
            1,
            "No such $OpenSSLBin!",
        );
    }
    elsif ( !-x $OpenSSLBin ) {
        $Self->False(
            1,
            "$OpenSSLBin not executable!",
        );
    }
    elsif ( !-e $CertPath ) {
        $Self->False(
            1,
            "No such $CertPath!",
        );
    }
    elsif ( !-d $CertPath ) {
        $Self->False(
            1,
            "No such $CertPath directory!",
        );
    }
    elsif ( !-w $CertPath ) {
        $Self->False(
            1,
            "$CertPath not writable!",
        );
    }
    elsif ( !-e $PrivatePath ) {
        $Self->False(
            1,
            "No such $PrivatePath!",
        );
    }
    elsif ( !-d $Self->{PrivatePath} ) {
        $Self->False(
            1,
            "No such $PrivatePath directory!",
        );
    }
    elsif ( !-w $PrivatePath ) {
        $Self->False(
            1,
            "$PrivatePath not writable!",
        );
    }
    return 1;
}

#
# Setup environment
#

# OpenSSL 0.9.x hashes
my $Check1Hash       = '980a83c7';
my $Check2Hash       = '999bcb2f';
my $OTRSRootCAHash   = '1a01713f';
my $OTRSRDCAHash     = '7807c24e';
my $OTRSLabCAHash    = '2fc24258';
my $OTRSUserCertHash = 'eab039b6';

# OpenSSL 1.0.0 hashes
if ($UseNewHashes) {
    $Check1Hash       = 'f62a2257';
    $Check2Hash       = '35c7d865';
    $OTRSRootCAHash   = '7835cf94';
    $OTRSRDCAHash     = 'b5d19fb9';
    $OTRSLabCAHash    = '19545811';
    $OTRSUserCertHash = '4d400195';
}

# certificates
my @Certificates = (
    {
        CertificateName       => 'Check1',
        CertificateHash       => $Check1Hash,
        CertificateFileName   => 'SMIMECertificate-1.asc',
        PrivateKeyFileName    => 'SMIMEPrivateKey-1.asc',
        PrivateSecretFileName => 'SMIMEPrivateKeyPass-1.asc',
    },
    {
        CertificateName       => 'Check2',
        CertificateHash       => $Check2Hash,
        CertificateFileName   => 'SMIMECertificate-2.asc',
        PrivateKeyFileName    => 'SMIMEPrivateKey-2.asc',
        PrivateSecretFileName => 'SMIMEPrivateKeyPass-2.asc',
    },
    {
        CertificateName       => 'OTRSUserCert',
        CertificateHash       => $OTRSUserCertHash,
        CertificateFileName   => 'SMIMECertificate-smimeuser1.crt',
        PrivateKeyFileName    => 'SMIMEPrivateKey-smimeuser1.pem',
        PrivateSecretFileName => 'SMIMEPrivateKeyPass-smimeuser1.crt',
    },
    {
        CertificateName       => 'OTRSLabCA',
        CertificateHash       => $OTRSLabCAHash,
        CertificateFileName   => 'SMIMECACertificate-OTRSLab.crt',
        PrivateKeyFileName    => 'SMIMECAPrivateKey-OTRSLab.pem',
        PrivateSecretFileName => 'SMIMECAPrivateKeyPass-OTRSLab.crt',
    },
    {
        CertificateName       => 'OTRSRDCA',
        CertificateHash       => $OTRSRDCAHash,
        CertificateFileName   => 'SMIMECACertificate-OTRSRD.crt',
        PrivateKeyFileName    => 'SMIMECAPrivateKey-OTRSRD.pem',
        PrivateSecretFileName => 'SMIMECAPrivateKeyPass-OTRSRD.crt',
    },
    {
        CertificateName       => 'OTRSRootCA',
        CertificateHash       => $OTRSRootCAHash,
        CertificateFileName   => 'SMIMECACertificate-OTRSRoot.crt',
        PrivateKeyFileName    => 'SMIMECAPrivateKey-OTRSRoot.pem',
        PrivateSecretFileName => 'SMIMECAPrivateKeyPass-OTRSRoot.crt',
    },
);

# add chain certificates
for my $Certificate (@Certificates) {

    # add certificate ...
    my $CertString = $MainObject->FileRead(
        Directory => $ConfigObject->Get('Home') . "/scripts/test/sample/SMIME/",
        Filename  => $Certificate->{CertificateFileName},
    );
    my %Result = $SMIMEObject->CertificateAdd( Certificate => ${$CertString} );
    $Self->True(
        $Result{Successful} || '',
        "#$Certificate->{CertificateName} CertificateAdd() - $Result{Message}",
    );

    # add private key
    my $KeyString = $MainObject->FileRead(
        Directory => $ConfigObject->Get('Home') . "/scripts/test/sample/SMIME/",
        Filename  => $Certificate->{PrivateKeyFileName},
    );
    my $Secret = $MainObject->FileRead(
        Directory => $ConfigObject->Get('Home') . "/scripts/test/sample/SMIME/",
        Filename  => $Certificate->{PrivateSecretFileName},
    );
    %Result = $SMIMEObject->PrivateAdd(
        Private => ${$KeyString},
        Secret  => ${$Secret},
    );
    $Self->True(
        $Result{Successful} || '',
        "#$Certificate->{CertificateName} PrivateAdd()",
    );
}

#
# actual tests
#

my $CryptObject = $Kernel::OM->Get('Kernel::System::Crypt::SMIME');

my @CertList = $CryptObject->CertificateList();

my $Cert1 = $CertList[0];
my $Cert2 = $CertList[1];

my %Cert1Attributes = $CryptObject->CertificateAttributes(
    Certificate => $CryptObject->CertificateGet( Filename => $Cert1 ),
    Filename    => $Cert1,
);
my %Cert2Attributes = $CryptObject->CertificateAttributes(
    Certificate => $CryptObject->CertificateGet( Filename => $Cert2 ),
    Filename    => $Cert2,
);

my @Data = $CryptObject->SignerCertRelationGet(
    CertFingerprint => $Cert1Attributes{Fingerprint},
);
$Self->False(
    @Data ? 1 : 0,
    'Certificate 1 has no relations',
);
@Data = $CryptObject->SignerCertRelationGet(
    CertFingerprint => $Cert2Attributes{Fingerprint},
);
$Self->False(
    @Data ? 1 : 0,
    'Certificate 2 has no relations',
);

$CryptObject->SignerCertRelationAdd(
    CertFingerprint => $Cert1Attributes{Fingerprint},
    CAFingerprint   => $Cert2Attributes{Fingerprint},
    UserID          => 1,
);

@Data = $CryptObject->SignerCertRelationGet(
    CertFingerprint => $Cert1Attributes{Fingerprint},
);
$Self->True(
    @Data ? 1 : 0,
    'Certificate 1 has relations',
);

my $Success = $CryptObject->CertificateRemove(
    Filename => $Cert2,
);
$Self->True(
    @Data ? 1 : 0,
    'Certificate 2 got removed',
);

@Data = $CryptObject->SignerCertRelationGet(
    CertFingerprint => $Cert1Attributes{Fingerprint},
);
$Self->False(
    @Data ? 1 : 0,
    'Certificate 1 has no relations',
);

# delete needed test directories
for my $Directory ( $CertPath, $PrivatePath ) {
    my $Success = rmtree( [$Directory] );
    $Self->True(
        $Success,
        "Directory deleted - '$Directory'",
    );
}

# cleanup is done by RestoreDatabase.

1;
