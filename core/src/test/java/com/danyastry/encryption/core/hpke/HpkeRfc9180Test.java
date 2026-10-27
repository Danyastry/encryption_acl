package com.danyastry.encryption.core.hpke;

import static org.assertj.core.api.Assertions.assertThat;

import com.danyastry.encryption.core.util.Hex;
import org.junit.jupiter.api.Test;

class HpkeRfc9180Test {

    private static final byte[] INFO = Hex.decode("4f6465206f6e2061204772656369616e2055726e");
    private static final byte[] PLAINTEXT = Hex.decode("4265617574792069732074727574682c20747275746820626561757479");

    @Test
    void baseModeMatchesAppendixA21() throws Exception {
        X25519KeyPair ephemeral = DhkemX25519.deriveKeyPair(Hex.decode("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b"));
        X25519KeyPair recipient = DhkemX25519.deriveKeyPair(Hex.decode("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df"));

        assertThat(Hex.encode(ephemeral.privateKey())).isEqualTo("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
        assertThat(Hex.encode(ephemeral.publicKey())).isEqualTo("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        assertThat(Hex.encode(recipient.privateKey())).isEqualTo("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
        assertThat(Hex.encode(recipient.publicKey())).isEqualTo("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");

        Encapsulation encapsulation = DhkemX25519.encap(recipient.publicKey(), ephemeral);
        assertThat(Hex.encode(encapsulation.enc())).isEqualTo("1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
        assertThat(Hex.encode(encapsulation.sharedSecret())).isEqualTo("0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7");
        assertThat(DhkemX25519.decap(encapsulation.enc(), recipient)).isEqualTo(encapsulation.sharedSecret());

        assertThat(Hex.encode(Hpke.keyScheduleContext(HpkeMode.BASE, INFO))).isEqualTo(
                "00431df6cd95e11ff49d7013563baf7f11588c75a6611ee2a4404a49306ae4cfc5b69c5718a60cc5876c358d3f7fc31ddb598503f67be58ea1e798c0bb19eb9796");
        HpkeContext sender = Hpke.keySchedule(HpkeMode.BASE, encapsulation.sharedSecret(), INFO);
        assertThat(Hex.encode(sender.key())).isEqualTo("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91");
        assertThat(Hex.encode(sender.baseNonce())).isEqualTo("5c4d98150661b848853b547f");
        assertThat(Hex.encode(sender.exporterSecret())).isEqualTo("a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922");

        assertThat(Hex.encode(sender.seal(Hex.decode("436f756e742d30"), PLAINTEXT)))
                .isEqualTo("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28");
        assertThat(Hex.encode(sender.seal(Hex.decode("436f756e742d31"), PLAINTEXT)))
                .isEqualTo("6b53c051e4199c518de79594e1c4ab18b96f081549d45ce015be002090bb119e85285337cc95ba5f59992dc98c");
        assertThat(Hex.encode(sender.seal(Hex.decode("436f756e742d32"), PLAINTEXT)))
                .isEqualTo("71146bd6795ccc9c49ce25dda112a48f202ad220559502cef1f34271e0cb4b02b4f10ecac6f48c32f878fae86b");
        sender.seal(Hex.decode("436f756e742d33"), PLAINTEXT);
        assertThat(Hex.encode(sender.seal(Hex.decode("436f756e742d34"), PLAINTEXT)))
                .isEqualTo("63357a2aa291f5a4e5f27db6baa2af8cf77427c7c1a909e0b37214dd47db122bb153495ff0b02e9e54a50dbe16");

        HpkeContext receiver = Hpke.keySchedule(HpkeMode.BASE, DhkemX25519.decap(encapsulation.enc(), recipient), INFO);
        assertThat(receiver.open(Hex.decode("436f756e742d30"),
                Hex.decode("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"))).isEqualTo(PLAINTEXT);
    }

    @Test
    void authModeMatchesAppendixA23() throws Exception {
        X25519KeyPair ephemeral = DhkemX25519.deriveKeyPair(Hex.decode("938d3daa5a8904540bc24f48ae90eed3f4f7f11839560597b55e7c9598c996c0"));
        X25519KeyPair recipient = DhkemX25519.deriveKeyPair(Hex.decode("64835d5ee64aa7aad57c6f2e4f758f7696617f8829e70bc9ac7a5ef95d1c756c"));
        X25519KeyPair sender = DhkemX25519.deriveKeyPair(Hex.decode("9d8f94537d5a3ddef71234c0baedfad4ca6861634d0b94c3007fed557ad17df6"));

        assertThat(Hex.encode(sender.publicKey())).isEqualTo("f0f4f9e96c54aeed3f323de8534fffd7e0577e4ce269896716bcb95643c8712b");
        assertThat(Hex.encode(recipient.publicKey())).isEqualTo("1a478716d63cb2e16786ee93004486dc151e988b34b475043d3e0175bdb01c44");

        Encapsulation encapsulation = DhkemX25519.authEncap(recipient.publicKey(), sender, ephemeral);
        assertThat(Hex.encode(encapsulation.enc())).isEqualTo("f7674cc8cd7baa5872d1f33dbaffe3314239f6197ddf5ded1746760bfc847e0e");
        assertThat(Hex.encode(encapsulation.sharedSecret())).isEqualTo("d2d67828c8bc9fa661cf15a31b3ebf1febe0cafef7abfaaca580aaf6d471e3eb");
        assertThat(DhkemX25519.authDecap(encapsulation.enc(), recipient, sender.publicKey())).isEqualTo(encapsulation.sharedSecret());

        HpkeContext context = Hpke.keySchedule(HpkeMode.AUTH, encapsulation.sharedSecret(), INFO);
        assertThat(Hex.encode(context.key())).isEqualTo("b071fd1136680600eb447a845a967d35e9db20749cdf9ce098bcc4deef4b1356");
        assertThat(Hex.encode(context.baseNonce())).isEqualTo("d20577dff16d7cea2c4bf780");
        assertThat(Hex.encode(context.exporterSecret())).isEqualTo("be2d93b82071318cdb88510037cf504344151f2f9b9da8ab48974d40a2251dd7");
        assertThat(Hex.encode(context.seal(Hex.decode("436f756e742d30"), PLAINTEXT)))
                .isEqualTo("ab1a13c9d4f01a87ec3440dbd756e2677bd2ecf9df0ce7ed73869b98e00c09be111cb9fdf077347aeb88e61bdf");
        assertThat(Hex.encode(context.seal(Hex.decode("436f756e742d31"), PLAINTEXT)))
                .isEqualTo("3265c7807ffff7fdace21659a2c6ccffee52a26d270c76468ed74202a65478bfaedfff9c2b7634e24f10b71016");
    }
}
