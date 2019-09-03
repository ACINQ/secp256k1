package org.bitcoin;

import com.google.common.io.BaseEncoding;
import org.junit.Test;

import java.util.Arrays;
import java.math.BigInteger;

import static org.bitcoin.NativeSecp256k1Util.*;

/**
 * This class holds test cases defined for testing this library.
 */
public class NativeSecp256k1Test {

    //TODO improve comments/add more tests
    NativeSecp256k1 nativeSecp = new NativeSecp256k1();

    /**
     * This tests verify() for a valid signature
     */
    @Test
    public void testVerifyPos() throws AssertFailException {
        boolean result = false;
        byte[] data = BaseEncoding.base16().lowerCase().decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()); //sha256hash of "testing"
        byte[] sig = BaseEncoding.base16().lowerCase().decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".toLowerCase());
        byte[] pub = BaseEncoding.base16().lowerCase().decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase());

        result = nativeSecp.verify(data, sig, pub);
        assertEquals(result, true, "testVerifyPos");

        byte[] sigCompact = BaseEncoding.base16().lowerCase().decode("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".toLowerCase());
        result = nativeSecp.verify(data, sigCompact, pub);
        assertEquals(result, true, "testVerifyPos");
    }

    /**
     * This tests verify() for a non-valid signature
     */
    @Test
    public void testVerifyNeg() throws AssertFailException {
        boolean result = false;
        byte[] data = BaseEncoding.base16().lowerCase().decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A91".toLowerCase()); //sha256hash of "testing"
        byte[] sig = BaseEncoding.base16().lowerCase().decode("3044022079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980220294F14E883B3F525B5367756C2A11EF6CF84B730B36C17CB0C56F0AAB2C98589".toLowerCase());
        byte[] pub = BaseEncoding.base16().lowerCase().decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase());

        result = nativeSecp.verify(data, sig, pub);
        //System.out.println(" TEST " + new BigInteger(1, resultbytes).toString(16));
        assertEquals(result, false, "testVerifyNeg");
    }

    /**
     * This tests secret key verify() for a valid secretkey
     */
    @Test
    public void testSecKeyVerifyPos() throws AssertFailException {
        boolean result = false;
        byte[] sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase());

        result = nativeSecp.secKeyVerify(sec);
        //System.out.println(" TEST " + new BigInteger(1, resultbytes).toString(16));
        assertEquals(result, true, "testSecKeyVerifyPos");
    }

    /**
     * This tests secret key verify() for an invalid secretkey
     */
    @Test
    public void testSecKeyVerifyNeg() throws AssertFailException {
        boolean result = false;
        byte[] sec = BaseEncoding.base16().lowerCase().decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".toLowerCase());

        result = nativeSecp.secKeyVerify(sec);
        //System.out.println(" TEST " + new BigInteger(1, resultbytes).toString(16));
        assertEquals(result, false, "testSecKeyVerifyNeg");
    }

    /**
     * This tests public key create() for a valid secretkey
     */
    @Test
    public void testPubKeyCreatePos() throws AssertFailException {
        byte[] sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase());

        byte[] resultArr = nativeSecp.computePubkey(sec);
        String pubkeyString = BaseEncoding.base16().upperCase().encode(resultArr);
        assertEquals(pubkeyString, "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6", "testPubKeyCreatePos");
    }

    /**
     * This tests public key create() for a invalid secretkey
     */
    @Test
    public void testPubKeyCreateNeg() throws AssertFailException {
        byte[] sec = BaseEncoding.base16().lowerCase().decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".toLowerCase());

        byte[] resultArr = nativeSecp.computePubkey(sec);
        String pubkeyString = BaseEncoding.base16().upperCase().encode(resultArr);
        assertEquals(pubkeyString, "", "testPubKeyCreateNeg");
    }

    @Test
    public void testPubKeyNegatePos() throws AssertFailException {
        byte[] sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase());
        byte[] pubkey = nativeSecp.computePubkey(sec);
        String pubkeyString = BaseEncoding.base16().upperCase().encode(pubkey);
        assertEquals(pubkeyString, "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6", "testPubKeyCreatePos");

        byte[] pubkey1 = nativeSecp.pubKeyNegate(pubkey);
        String pubkeyString1 = BaseEncoding.base16().upperCase().encode(pubkey1);
        assertEquals(pubkeyString1, "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2DDEFC12B6B8E73968536514302E69ED1DDB24B999EFEE79C12D03AB17E79E1989", "testPubKeyNegatePos");
    }

    /**
     * This tests public key create() for a valid secretkey
     */
    @Test
    public void testPubKeyParse() throws AssertFailException {
        byte[] pub = BaseEncoding.base16().lowerCase().decode("02C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D".toLowerCase());
        byte[] resultArr = nativeSecp.parsePubkey(pub);
        String pubkeyString = BaseEncoding.base16().upperCase().encode(resultArr);
        assertEquals(pubkeyString, "04C591A8FF19AC9C4E4E5793673B83123437E975285E7B442F4EE2654DFFCA5E2D2103ED494718C697AC9AEBCFD19612E224DB46661011863ED2FC54E71861E2A6", "testPubKeyAdd");
    }

    @Test
    public void testPubKeyAdd() throws AssertFailException {
        byte[] pub1 = BaseEncoding.base16().lowerCase().decode("041b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f70beaf8f588b541507fed6a642c5ab42dfdf8120a7f639de5122d47a69a8e8d1".toLowerCase());
        byte[] pub2 = BaseEncoding.base16().lowerCase().decode("044d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07662a3eada2d0fe208b6d257ceb0f064284662e857f57b66b54c198bd310ded36d0".toLowerCase());
        byte[] pub3 = nativeSecp.pubKeyAdd(pub1, pub2);
        String pubkeyString = BaseEncoding.base16().upperCase().encode(pub3);
        assertEquals(pubkeyString, "04531FE6068134503D2723133227C867AC8FA6C83C537E9A44C3C5BDBDCB1FE3379E92C265E71E481BA82A84675A47AC705A200FCD524E92D93B0E7386F26A5458", "testPubKeyAdd");
    }

    /**
     * This tests sign() for a valid secretkey
     */
    @Test
    public void testSignPos() throws AssertFailException {

        byte[] data = BaseEncoding.base16().lowerCase().decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()); //sha256hash of "testing"
        byte[] sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase());

        byte[] resultArr = nativeSecp.sign(data, sec);
        String sigString = BaseEncoding.base16().upperCase().encode(resultArr);
        assertEquals(sigString, "30440220182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A202201C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9", "testSignPos");
    }

    /**
     * This tests sign() for a invalid secretkey
     */
    @Test
    public void testSignNeg() throws AssertFailException {
        byte[] data = BaseEncoding.base16().lowerCase().decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()); //sha256hash of "testing"
        byte[] sec = BaseEncoding.base16().lowerCase().decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF".toLowerCase());

        byte[] resultArr = nativeSecp.sign(data, sec);
        String sigString = BaseEncoding.base16().upperCase().encode(resultArr);
        assertEquals(sigString, "", "testSignNeg");
    }

    @Test
    public void testSignCompactPos() throws AssertFailException {

        byte[] data = BaseEncoding.base16().lowerCase().decode("CF80CD8AED482D5D1527D7DC72FCEFF84E6326592848447D2DC0B0E87DFC9A90".toLowerCase()); //sha256hash of "testing"
        byte[] sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase());

        byte[] resultArr = nativeSecp.signCompact(data, sec);
        String sigString = BaseEncoding.base16().upperCase().encode(resultArr);
        assertEquals(sigString, "182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A21C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9", "testSignCompactPos");
        //assertEquals( sigString, "30 44 02 20 182A108E1448DC8F1FB467D06A0F3BB8EA0533584CB954EF8DA112F1D60E39A2 02 20 1C66F36DA211C087F3AF88B50EDF4F9BDAA6CF5FD6817E74DCA34DB12390C6E9" , "testSignPos");
    }

    @Test
    public void testPrivKeyTweakNegate() throws AssertFailException {
        byte[] sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase());
        byte[] sec1 = nativeSecp.privKeyNegate(sec);
        assertEquals(BaseEncoding.base16().upperCase().encode(sec1), "981A9A7DD677A622518DA068D66D5F824E5F22F084B8A0E2F195B5662F300C11", "testPrivKeyNegate");
        byte[] sec2 = nativeSecp.privKeyNegate(sec1);
        assert (Arrays.equals(sec, sec2));
    }

    /**
     * This tests private key tweak-add
     */
    @Test
    public void testPrivKeyTweakAdd_1() throws AssertFailException {
        byte[] sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase());
        byte[] data = BaseEncoding.base16().lowerCase().decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".toLowerCase()); //sha256hash of "tweak"

        byte[] resultArr = nativeSecp.privKeyTweakAdd(sec, data);
        String sigString = BaseEncoding.base16().upperCase().encode(resultArr);
        assertEquals(sigString, "A168571E189E6F9A7E2D657A4B53AE99B909F7E712D1C23CED28093CD57C88F3", "testPrivKeyAdd_1");
    }

    /**
     * This tests private key tweak-mul
     */
    @Test
    public void testPrivKeyTweakMul_1() throws AssertFailException {
        byte[] sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase());
        byte[] data = BaseEncoding.base16().lowerCase().decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".toLowerCase()); //sha256hash of "tweak"

        byte[] resultArr = nativeSecp.privKeyTweakMul(sec, data);
        String sigString = BaseEncoding.base16().upperCase().encode(resultArr);
        assertEquals(sigString, "97F8184235F101550F3C71C927507651BD3F1CDB4A5A33B8986ACF0DEE20FFFC", "testPrivKeyMul_1");
    }

    /**
     * This tests private key tweak-add uncompressed
     */
    @Test
    public void testPrivKeyTweakAdd_2() throws AssertFailException {
        byte[] pub = BaseEncoding.base16().lowerCase().decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase());
        byte[] data = BaseEncoding.base16().lowerCase().decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".toLowerCase()); //sha256hash of "tweak"

        byte[] resultArr = nativeSecp.pubKeyTweakAdd(pub, data);
        String sigString = BaseEncoding.base16().upperCase().encode(resultArr);
        assertEquals(sigString, "0411C6790F4B663CCE607BAAE08C43557EDC1A4D11D88DFCB3D841D0C6A941AF525A268E2A863C148555C48FB5FBA368E88718A46E205FABC3DBA2CCFFAB0796EF", "testPrivKeyAdd_2");
    }

    /**
     * This tests private key tweak-mul uncompressed
     */
    @Test
    public void testPrivKeyTweakMul_2() throws AssertFailException {
        byte[] pub = BaseEncoding.base16().lowerCase().decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase());
        byte[] data = BaseEncoding.base16().lowerCase().decode("3982F19BEF1615BCCFBB05E321C10E1D4CBA3DF0E841C2E41EEB6016347653C3".toLowerCase()); //sha256hash of "tweak"

        byte[] resultArr = nativeSecp.pubKeyTweakMul(pub, data);
        String sigString = BaseEncoding.base16().upperCase().encode(resultArr);
        assertEquals(sigString, "04E0FE6FE55EBCA626B98A807F6CAF654139E14E5E3698F01A9A658E21DC1D2791EC060D4F412A794D5370F672BC94B722640B5F76914151CFCA6E712CA48CC589", "testPrivKeyMul_2");
    }

    /**
     * This tests seed randomization
     */
    @Test
    public void testRandomize() throws AssertFailException {
        byte[] seed = BaseEncoding.base16().lowerCase().decode("A441B15FE9A3CF56661190A0B93B9DEC7D04127288CC87250967CF3B52894D11".toLowerCase()); //sha256hash of "random"
        boolean result = nativeSecp.randomize(seed);
        assertEquals(result, true, "testRandomize");
    }

    @Test
    public void testCreateECDHSecret() throws AssertFailException {

        byte[] sec = BaseEncoding.base16().lowerCase().decode("67E56582298859DDAE725F972992A07C6C4FB9F62A8FFF58CE3CA926A1063530".toLowerCase());
        byte[] pub = BaseEncoding.base16().lowerCase().decode("040A629506E1B65CD9D2E0BA9C75DF9C4FED0DB16DC9625ED14397F0AFC836FAE595DC53F8B0EFE61E703075BD9B143BAC75EC0E19F82A2208CAEB32BE53414C40".toLowerCase());

        byte[] resultArr = nativeSecp.createECDHSecret(sec, pub);
        String ecdhString = BaseEncoding.base16().upperCase().encode(resultArr);
        assertEquals(ecdhString, "2A2A67007A926E6594AF3EB564FC74005B37A9C8AEF2033C4552051B5C87F043", "testCreateECDHSecret");
    }
}
