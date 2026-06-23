#include <stdint.h>
#include <string.h>
#include <check.h>
#include "shrincs/shrincs.h"

static inline int hex_char_to_int(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

int hex_to_bytes(const char* hex_str, uint8_t* out_buffer, size_t max_len) {
    if (!hex_str || !out_buffer) return -1;

    if (hex_str[0] == '0' && (hex_str[1] == 'x' || hex_str[1] == 'X')) {
        hex_str += 2;
    }

    size_t hex_len = strlen(hex_str);

    if (hex_len % 2 != 0) {
        return -1; 
    }

    size_t expected_bytes = hex_len / 2;
    
    if (expected_bytes > max_len) {
        return -1;
    }

    for (size_t i = 0; i < expected_bytes; i++) {
        int high_nibble = hex_char_to_int(hex_str[i * 2]);
        int low_nibble  = hex_char_to_int(hex_str[i * 2 + 1]);

        if (high_nibble == -1 || low_nibble == -1) {
            return -1;
        }

        out_buffer[i] = (uint8_t)((high_nibble << 4) | low_nibble);
    }

    return (int)expected_bytes;
}

START_TEST(test_shrincs_stateless_verify) {

    SecretKey sk;
    PublicKey pk;

    hex_to_bytes("a8e287adc1501ea848d9e29fce044696", pk.seed, N);
    hex_to_bytes("2a398eeb0b9f7ae63d800cfc44269216", pk.root, N);

    sk.pk = pk;
    hex_to_bytes("4fafefabe52a6901d337891cff82c1f4", sk.sf, N);
    hex_to_bytes("87949c05568aa0e60f27404495331f87", sk.sl, N);
    hex_to_bytes("d8bba1df302d6fd11e55d3722cc30444", sk.prf, N);
    hex_to_bytes("bff2c44071fb7bc882a9ce3e8e439db7", sk.seed, N);

    uint8_t message[32] = {0};

    uint8_t sl_signature[SL_SIZE];

    hex_to_bytes("4fafefabe52a6901d337891cff82c1f40dd249f70aaa18029f433097d57930a38f9d3f6c7d994e2db1a0dc41f4928a827e5cd6040f22c15515604ea548cbd58ea122b40962079134b01076c3e0f6652957c799c2048a8778eabfe3c64b3f2a08711a00fd1765954ebe997c85ae56b4eeff1b73639b552e4a2994ca61e8cae8102bcc958a8d21214514c99a1629f211c6d52f795184cc55c15bbd5fbe9b5f4a051f68e7b73689aaa24b8d1e996f169e10cf1158fdd0f46d4c92e55489ab17317c8d575d91707c1d3cdd274880b83e2ce8e2a8fa4d05cdbefc142053dd158167cf97af9cc751bb1253e8929c8706cbb621f67747b0750a5f3494f2ee77220c7e9f6b951c1b1caf35d44a8af572442aeaa12fe6088c62fd25537761e77b6d2351c7e1810bf460da6cb00a228a705d7752f0f6cdad2bae3faa1b91585a2c3aad536e6cbfb63c3010ef0b6906cba8e63a2ecebf3ad1d1e7ff2d652dec19700020353e8c3f279424b25fb6e5e53200d5d40b763922b4156cd1fa511df59cfd770f90667ebdde0e5c5d00dd06bdfb86a14219aa5fb6c3a4b11727eefd2d3ef310c69c2f049c41499b9aafcab4c26ecdd7a687301e99bbfaff8fe74cd5c96f31f800fa195c763e9be9efb04a18359e344b549aa83f047a169d9728685b176b19c24e4e680f65440715f5e925da3e7d345e3285754405c2e1044451f3a5884c83fe587edc4cae08465eb69514dbd6f1b4e8648f84d47c1ea7bd61eaa69f1855eec97271a9c5a843d6b33301682fb466c9ebc3d423a2582468117610aaea4c484bb6b47988ef6241964b77680739637e143e5af57c008195346a3d62be3a62a04003691132d100e4abacfa9d0720dc91384eb7c8af75b54e484bb60d6eb1168f4bd42412527929f9914526d30a6f7a4ea0b7e002a27b725bfd2631395be2e2d29a8f0d1db0c62ae154c41a46ab4f8c087e8dfaafa897e07441b7c8c5295053daf57f797c53a22488b320f2cbd67fb05768b76fa36b2d46047a2f4943cd9d7f8772244a9045dbeadd621e7bc554486b07e735c5d93d2c9a111178d67cd5cbfb4734006116c24599521bd41f7b0c0638a5e5847fe12645fc483c8948756b4b238a898fe31d79e937ead80148d1c63efb33f6182168b38846679a944722c5ca1994e322b4072cd591a8f67fc936836a7903d101613d4e1656526e9acab2da206385eb0ff375b9d0c9bc3b770b9ef491c8f2b6d3b3e4744bdbaa5dc45f86f90f9c1c9973a3ff691f9b709b9165291aaddf083d38176566566f2dc442debebdcc91b517dc1d43052ff3c8d4eb6160ad2c71eb7021f4faeddd4c7bea22db8408adc2abe1ff5fb78c35ed012323bd2060f8e39e2f56f35d22a97ee4d2b72d2795dd94382aa07e8ea06dd5f1d0f93aba5ce1361592f7fca7d5207f0bc7243b3806fd2ebe82b6ac153c67654f9bac40f3c678ae1dddee168594f88971dd912778313e11fe9d033973d8c9ef2f4d4a67bc8b97cb22facab305f84174f9278da1f1e8951f91e31d47c477447eac5fbc3c00c7a4311eb99eac879371b87564c787b2c6117f5b8ad5fc72cadd05d2ccc63b0e08a37f594293227443a69cb443b2dc9272b508d9cf6052765caeef1dfa649be70ad42219a42e4c7f78cba005ca3ab22b97cd64a432b5496f9f01421ebf3c892e47997ac53ad5ac968c120658c2f21ef9853aaf0165066f1111d944cc750f39691870d3c6410dc6fe044ed1c930249c91bdcd0aab6be759b386c9e02fd4d97e959970045cd11f1ce27bc5db4eca072b45f087320d4481417da3b51af718ac22bd6da2ef79acbed8080f7b4bfdf2a9f380609168ac262371a3acece686ec6d1eadbb5faca44e548bacdbb8728628762f333ee51b83374a5667c1f0b4667e0c250849a747c10c7db7d851591d638ce2ef4f797f163654529a70ef875956403a774d471acfffe063504afd1a2565f35a02aef54a45750323aa350de1bf005478ed2fbdfd254fa06e2e59254ab6ec6cb8778e938b86e9ff257ac8b6cf59c698a754acdb06bd877f1c839d77952683e13735a15079df18df708110d690012fbc02119751461f403b19fd620145d0fc907bbd2d10af169ce856e3c5cb9dc5f1eb9e8e9de433b5c7b524bffdc129a1f26846d0b88a52e56abaaa54892beda55f02c596c65250e092f8a389382bf43d5b15df23eb2448aabf26b2a2d140a94c259516f6e63d443aeb029f3b4b2800d83eebe9d74e3f5003b34ef8e301bce874e74f5c8b30408d3bf6178c2c7f32ab033b5f220eaa6618a08be955c41db8f8cd8ac4e03d34cb42113cbadb06f46f17724552dcd1228659523f9c57fa9c50ffebf391fc45ca69a131286c33415f582e570f65db89ebcf828e90f261bac5bd9e7d22c700e45264ffd0eded3b70016874cf88ddd4b1a36564170e124fe4ebfca18d45c589ecec36acfe944938586b47cd2a711f08a2113346212b64a41897cb52651de717fac0fca277e6a04a20750cb0d801babe1ac2db415a9d6f15542749b8c726f52b8865c200280cb26bfcabd07cda8c333437860107d00609d20f0f9ad2ddb5615f7d28d337d5ae716ed0e95028d778200ea7eb3bcc810f3e7bf16c2a0d6e6d9e42ee7bb6067c5f7f910d56f408063078fd8d02c38fe441a03b233452dc337c91444b97ac7f60ad1d278b97130d82421b39a0aaedbbff6345d91240028e8a2372f91c7d1340651f83887ea14c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004cf664b81dc1c1243531bf067b4a86121fb3016b883538deaa6bd5751a8962eb0000015391443938afd0f2a73e7d6848143bc125c468ddc4e35c84e1e88fc37fd2217a294a34a390ca00efd04b69177466e105ebc0c84230cb1e0018041ad58e773dec143dc51b8f9a535e2ac864cf5be1f05db79687b4ad3abed95a6917bba8adc0debe706f776cb4a14b31d88d6df9e1a0dd4793e42d7a1a6a6fc7b61ea7c071dd296ecf3ce1fc21b21f43ab84baca1b21d0f222994d4318718b07c035c2496378b12c56a5fcafeda77b3b7b7a960e7a9e255e4c333628c52abaadd994e0b8bf51de5cd1382a82bf045a2072494a514ff3d201bfb09e9671457592a05d76e82f30139bdcb49d2b76dd24da3c67a01dedddbb37c3299f5740b213014163cd78c9f15d13eb1cb86cf1f2dcd436d8518521a6146ac82101ee7d6fea80943d09fabcc67cd22e69ceff3e3ec8152fc9a350f95dd53a36176e87c0e09b827c134a6e98797cab1eccf94eb52f48fda8c42b6de39f944bab243121e62c3523feff0caceff911d21ea35b9ed75e4f62b309b2a6379462cee148e4c931bad1f01ea7853056f35d409d932c4561e802a6f5133922a9a545fec8dd31749a88f2c15accb8da12b687b9000001d3c443ae0a8966d1b89274d4fe55e49ad960dadb3cc1f4349aa8840b0c0aba8c54e3243cf29cb75b7428b166084eb289c5d50d3a0bb4737c8ad1c8c0bebede9097e0ffafa233fd07d73e6eed94e039519e505df8e7c99a611eba874b3d4255eb9fa5098607525853b2f1f7ebd3e8faae27a18e8dfe3ada76a786f2a3912a447eff08e020b41c8fc96cbb1fc74efbeb89fa3d0b6d8c978b563113c624761aa1e9f88ef7ddf62161320426c26ed676e3e3fc9ede6c237db97312d48434acec3cd7d89443d0268301cb0a9cdcd5bde37a943a261c8d681237f56bc6af069350e92c6a3e9dc18e6f6cec78cb4b97717a38da7cb2781b2f5b5da6b325580b43ff5ae738a25d7e8767ed1973ca3f30a8968ae26cb2671dc7ef77f8ce66e1bf500aaf1f29ef5328f5dbea503b0ec65f8cac6140a09bfe4c1de13ec16600e0762bc69781e1a8e27690f43541ad4b83e6354997aea514ad812d229b3ee85f4cbbab25fb1b5fedad79431afd2dfaff6e4d56b0e0f7541258ff97824cc88da956280265b7223e7b994de4f6a3c9ebb730996f8c04fa880cfc3625f7b8753773272c00448bbe64000008e685a1100973c78ef77365cf149d1fcbfe226491cc426635eb3f7699b40ed8c24b0057bdfb030d2f6cfd2385ffc3a2732367ce1b5aab2dac3612616c8b821fd593dad5345fa62d3012912d8b32697ca409795b8d770c41f2feeeb8e2b910f156b7911e1bfd950e610776b19f6d3a3bf1aaef5eaf6b4bcd557c51d146b98457b51539a482ec2b27818240842e801ac946ef6fbf49957e745c91223d12657e546a142fddaf708f7901b3b486cd99ef7320f2e631368d674fe1e2863c8b0ddb723268fe3cddcee1a1bc854e286bc82025f2e32ed68b650a8c77e120fca729a17795c564c33576b9d435d7437641c9a7f5c32ef23f85d8e8525f02a50e26af240fb1a867bd4fd8661263ba2d02bc5bfbb382948f5e248180aba33cb2918bac6d296fcc5160c60e5ec389f7cd132cbd5a755cc90951f08f0e957e745327b80213630105c36abb75a87aab306d4922232b7f332c863baa2832666d556adeb7b77e11a4b843521ec4335778205ccf99a858aef20856b0ea5ab1cfdc3a4c6c6cb7a46e67bc70144cbd6e7459a3724cbdf5cf6c05ee11998f4c9ab6253859b7152fc7b3d29b000000fc73c6d6f30657361b63e1d5ece3a5e4e0eb6ab79977ba197bc18a4cd4443527e0616afacb3f2b155cc0b7741d6b51f89d3475b2b23167908c51efca58a117ecbdb0e5e40afffaeb4f31966ab445f1787dcd588f719d7fda72c22370471172d9c3a66308252152eb1554332add4ec05fdf9c72d54e3d122c33f5b5e406c2e257781dc6d28c45c108531cdb731d30538bb2d781a6212dafe09e169737de8cd07e127d7d24c276427004a728f0b79925e7d3a4603f5290bda19d8ef32f95c743f83b8d77f51b8b86b52c745c4b493f4542c7d271f99e5422b5c04c915129a35065e62d55704dabfc42eb9f45f02ade8733bd3970a5b93b3842508d555f5a20e505d31f7c5046fd2b52ab7fa9152fe3b9a9c967ce72a6e067b8de73f755854f0706d904a9b8cce3804b0bb6fc22febb3fb0bc7290c2aa896fc55be50719c8d2deef8d2ea1c489ebbc89e5d6accebeaea5e3fa0c2c686da6cef330e4a87db5f9aa019676d2f15804da2f653561159c9d624b0020245e68864a48c43a959ed7b05f4076", sl_signature, SL_SIZE);

    ck_assert_int_eq(shrincs_verify(message, 32, sl_signature, SL_SIZE, &pk, 2040), 1);
}
END_TEST

START_TEST(test_shrincs_stateful_verify) {

    SecretKey sk;
    PublicKey pk;
    State state;

    state.q = 1;
    state.valid = 1;

    hex_to_bytes("a8e287adc1501ea848d9e29fce044696", pk.seed, N);
    hex_to_bytes("2a398eeb0b9f7ae63d800cfc44269216", pk.root, N);

    sk.pk = pk;
    hex_to_bytes("4fafefabe52a6901d337891cff82c1f4", sk.sf, N);
    hex_to_bytes("87949c05568aa0e60f27404495331f87", sk.sl, N);
    hex_to_bytes("d8bba1df302d6fd11e55d3722cc30444", sk.prf, N);
    hex_to_bytes("bff2c44071fb7bc882a9ce3e8e439db7", sk.seed, N);

    uint8_t message[32] = {0};

    uint32_t sf_size = N + WOTS_SIGN_LEN + state.q * N;

    uint8_t sf_signature[sf_size];

    hex_to_bytes("87949c05568aa0e60f27404495331f870092ebeeff881cb51cc9269b0af00d1309c7c8e2508f0eb712c80cccf25891a600000300e8d7d604d0e378f9caed4a168f3e229a6ebf94e00ccbca02af0cd178623aa135700d740ca2b1e149ffc097fd504bc5bd2d568b50998cc1efdd41223fcbcfd1976e24cfca9e43c7324d4a42cb73d97836a4f1c6188de2a876dccb1557175342722a1aad240cd68ed60b0b5ec2dda06f90819ac27a7eeacb83346492e9cf26c2b11cd2c056d6b1de89d5cd26773dd72a6ad1c38f32d466c07ced2c892dc51e30ca0d2da66f03bf495dfe33ffab763123a8e8a2974776d017abaf94c4f595fdcb838067de061c264c479755b4efff321a38c7613b3a380a63113e50a20de4e7d28dba35d87a18a435780994f8f3979a9c0e1368ef3b3cb569dd864132f6377f95a02da28b3f3baec83da2151384f7ed35f3", sf_signature, sf_size);

    ck_assert_int_eq(shrincs_verify(message, 32, sf_signature, sf_size, &pk, 2040), 1);
}
END_TEST

START_TEST(test_shrincs_stateless_sign) {
    SecretKey sk;
    PublicKey pk;
    State state;

    shrincs_key_gen(&pk, &sk, &state);

    uint8_t message[32] = {0};

    uint8_t sl_signature[SL_SIZE];

    ck_assert_int_eq(shrincs_sign_stateless(message, 32, &sk, sl_signature, NULL, NULL), 1);

    ck_assert_int_eq(shrincs_verify(message, 32, sl_signature, SL_SIZE, &pk, 2040), 1);
}
END_TEST

START_TEST(test_shrincs_stateful_sign) {
    SecretKey sk;
    PublicKey pk;
    State state;

    shrincs_key_gen(&pk, &sk, &state);

    uint8_t message[32] = {0};

    uint32_t sf_size = N + WOTS_SIGN_LEN + (state.q + 1) * N;

    uint8_t sf_signature[sf_size];

    ck_assert_int_eq(shrincs_sign_stateful(message, 32, &sk, &state, sf_signature, 2040, NULL, NULL), 1);

    ck_assert_int_eq(shrincs_verify(message, 32, sf_signature, sf_size, &pk, 2040), 1);
}
END_TEST

Suite * shrincs_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("SHRINCS");

    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_shrincs_stateless_verify);
    tcase_add_test(tc_core, test_shrincs_stateful_verify);
    tcase_add_test(tc_core, test_shrincs_stateless_sign);
    tcase_add_test(tc_core, test_shrincs_stateful_sign);

    suite_add_tcase(s, tc_core);

    return s;
}

int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = shrincs_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? 0 : 1;
}