// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: https://pvs-studio.com

#include <array>
#include <cassert>
#include <filesystem>
#include <format>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <winapi++.h>

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::wstring;
using std::string_view;
using std::vector;
using std::format;
using std::array;
using std::ifstream;

using namespace std::string_literals;
using namespace std::string_view_literals;

namespace fs = std::filesystem;


WinCppCrypt::ByteBuffer readEntireFile(string_view file_path)
{
    fs::path p1 = file_path;
    // Open file in binary mode
    auto file = ifstream(p1, std::ios::binary);
    if (!file)
    {
        auto msg = format("Failed to open file: {}", file_path);
        throw std::runtime_error(msg);
    }

    // Move the file pointer to the end to get the size
    file.seekg(0, std::ios::end);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    // Read the file contents into a vector
    std::vector<unsigned char> buffer((const unsigned __int64)size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size))
    {
        throw std::runtime_error("Failed to read file: ");
    }

    return buffer;
}

bool testEncodeDecodeBase64File()
{
    using namespace WinCppCrypt;
    auto file_data = readEntireFile("C:\\Windows\\System32\\calc.exe");

    // calculate sha256 file
    auto hash_original = SHA256::generate(file_data);

    // encrypt file
    auto ciphertext = AES256_GCM::encrypt(file_data, "Passw0rd", {});

    // decrypt file
    auto plaintext = AES256_GCM::decrypt(ciphertext.unwrap(), "Passw0rd");

    // calculate again sha256 of decrypted file
    auto hash_decrypted = SHA256::generate(plaintext.unwrap().plaintext);

    auto b1 = Util::base64Encode(hash_original.unwrap());
    auto b2 = Util::base64Encode(hash_decrypted.unwrap());

    return b1.unwrap() == b2.unwrap();

}

bool testEncodeDecodeBase64BinData()
{
    unsigned char bin_data[] = {
        0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };

    auto res_enc = WinCppCrypt::Util::base64Encode(bin_data, sizeof(bin_data));
    if (res_enc.hasError())
    {
        return false;
    }

    auto res_dec = WinCppCrypt::Util::base64Decode(res_enc.unwrap());
    if (res_dec.hasError())
    {
        return false;
    }

    if (std::memcmp(bin_data, res_dec.unwrap().data(), res_dec.unwrap().size()) != 0)
    {
        return false;
    }

    return true;
}

bool testEncodeDecodeBase64()
{
    using namespace WinCppCrypt;
    using namespace WinCppCrypt::Util;

    auto msg = R"(
12345
54321
dog cat
goose bed,
hello LMAO 😂😂😂
こんにちは 🙇🏻‍♂️🙇🏻‍♂️
)"s;
    //msg = "hello";

    auto encoded = base64Encode(msg);
    if (encoded.hasError()) return false;

    auto decoded = base64Decode(encoded.unwrap());

    //cout << "Original: '" << msg << "'\n";
    //cout << "Encoded:  " << toSv(encoded) << "\n";
    //cout << "Decoded:  '" << toSv(decoded) << "'\n";

    //cout << "Result: ";
    //if (msg.size() == decoded.size()
    //    and
    //    std::memcmp(msg.data(), decoded.data(), decoded.size()) == 0
    //    )
    //{
    //    cout << "Success!\n";
    //}
    //else
    //{
    //    cout << "Fail :(\n";
    //}

    bool res =
        (msg.size() == decoded.unwrap().size())
        and
        (std::memcmp(msg.data(), decoded.unwrap().data(), decoded.unwrap().size()) == 0);

    return res;
}

bool testSHA256()
{
    auto convert = [](string_view input)
    {
        size_t len = input.size();

        auto res = WinCppCrypt::ByteBuffer();
        res.reserve(len);

        std::stringstream ss;

        for (size_t i = 0;
             i <= len - 2;
             i += 2)
        {
            int value = 0;
            string_view hex_string = input.substr(i, 2);

            ss << std::hex << hex_string;
            ss >> value;

            res.push_back(static_cast<WinCppCrypt::byte>(value));

            ss.clear(), ss.str("");
        }

        return res;
    };

    using namespace WinCppCrypt;
    using namespace WinCppCrypt::Util;

    struct Hash_Test
    {
        string_view input;
        string_view expected_hash;
    };

    // generated with python
    Hash_Test le_test[] = {
        {
            .input = "Bfqkdc qOeTfpK aXGimBV VNRuPUu rYLq eew DFY fGHJ nxT UIkWCgRRS RPg LQvJwURffO LmWSEsZ HuhICaYR Berual gKcntcX AHJWWRnFe naUjpYd hvMxDyWd DFhApDkyCX qQwJ KNObDYOPJ OnkUgrFYnb oHf pdvmJ ZYHPovzB kWqmebY howlTpEZc AokUNHaJsz LnrtEB tUG cFwRaTsbEt SRoNanF hToxZXvy ufLustani dTlsw OYjnUwqET PeAeyNAqm awcjRu TTJ nCID ebNKbAcV pEOemHTwL hmfuRIMxv xIENmwP dMii jsWNTm TtihT FDWGRFPQs WtUOO aXdWd CHpUq IENqsJ Ukm ogYqllXmlB LGJQuQh VaRcJe AZNhhQ msChNADmfb QSRcSD MdKor VEBzIOu bOhlEoPLBo EbBvCHEMiC ngLFAKwtmE IsZT DpflJ mJV vqKLOEJkWR LKuMm nsyMj IEZOgxxGt zwSCKp KNejGJ BBzQwrQ GbGetFs PByWeyKG rOMWYBa LfvAcIf bQDRct gvyZGoionH QoM QaS tVxegZTca FZly SCWUaW RQBPNK zWJoT WfAb vSoPI YNLLc BOL pvReSQK PFwg LmLSfq NNnek IPn SJzj lnlJfuMOt SDiRqoQb iGIjLeDwab uqTfsJ PEbjl JoeCxImg rxv KaJC EShFqg rZWPNplQ zELYp Ico jcoTfc TwquvZZtmT PcSQur ISGtq Fdyn ncmKOWST BaIedae iLEl RIqgAyc cPClX eTemrS teQQ QbBsWbz JdvnH XXcGTDfh xKvIDg GALG iAWi QdwNpV DxKru gvVK cSCewjt CdFTdkMHZB dnlAmtjM mEIsmC ADSywM GZljKvguRH UOLvfCN WWJhvhxEnY HEhgW xHGGaC gFIIQ AUJQPAfylz JuJePShwsG NTeoVd UvGxke zEik giXT OTziuc CHx KWf BvVEJFVZYd Vtrok rTIvrGEiwU hXPXhA IXUGHcOG oLKn JxFwKKHt idBeThBTf mEr XeJpcr yaPRPH Sfdn UrjvWBz YcwO RaSs Stdl QHKlo rwqbZkginp bvNdrXdO MGAVXakaC PnsNN jvNYep DQan WUpQxQz Knw SccRJ eqO fpuIKVLMr lRUuhcorI vkxvnTuK wfHOm",
            .expected_hash = "8e95105f52aa2b1c2e65a26587dbfb1b3e6994f052fb996a27b5828cfa04b453"
        },
        {
            .input = "DrRXseTb yoKtYHSP hefuEhWxO wUrLTcNZQ JRn bwLkkmsIbs UCq bhrhclT LfufzbxC kJiiMTCT pLXxz Xvcfyr BSDtVS Xux hVZzUscq KGQxFy Kca fvTBalTRFN XoZDcTC rLglmcObl oaSeGIj Vrge HKBCbL iaCyhsyL izJL hDy SUoKyxiH BDxPh LbCDjGCNTf jEONA Euw CNSHZcMTM BkstS PnKilvYVzk FmbZg eCtTVgqCY zIwZoUGI dLtq OtInchDCde iro fOjXD oCePHbRF zGMTFG OwlpM oHvGNFzlki eAPCGo yNKK JGNVa FHyJY ybvja TtLEqpNGV UdOTKgZV ryDixOlC hJj RdFgWFdH ICzXByXYb MojNdun rTjuvZPjLa kfoUMAoAc ySSga xITT SCw VACSmOtHQj aTQjgFYR EgGaNY lnBI jNqT QheIxeJPNx xgZCGwo odhGBLSZgq jrFKCKngI FKGdcgQUJ UquzM YRdXwUS qUgbXdAVFP ZVWIq XrrFfAzQr iUOV jAYP XWJJgE Don QDgWL QKFVUDG YDyoxkCLRs yRnzotwNL AASxHu gFnREmY LqRB FarHh qXpKJkG TMOLav SYrKdRNjc lnLQMERSJg vVIDb Ueq tZskfPudB ytFi qXjHrXI RHklV xyNcDavYk XXMNtT DhZUR",
            .expected_hash = "be289ccc4b6fe61f31138f2799a3428347b9c4064922a8b94fd6f219bd8a4c6e"
        },
        {
            .input = "DnM IWQ ndPEpN wTYBxxSrix hsmoYJoomt zrsBgAERs JBBGpMBw bnkOIP NedKhf mYKasMz leokS ETaM bZp lhgV vsHpL rDTjSOEDz Dws FifSsiXB SWDOIWR RsDskkqPV mWgBAzcA kro TYXHLIpmS biMjbq AZfi nGKaD qKdhP EBFWIvmZl KSsCBp ZJOYjWVr NygnEAgg dUkmecMuyw ykFNOlQQ nDkeMMHg GESLcP SZrh CEObkfefw HRJmp HvyMmDolYR LNijUwFj DEwHMVDKa KmpmXHZBJ oFblxg edq YSUzMty HlBewOKH McDZ AwUu IsRa gFBlT Aabxh MrgDfyBzX QXsvORNNaK EIORhUsxQY bafym",
            .expected_hash = "ecbc6440b987ec0e878b2a9a91ef8638ca904c79d34a9b74b706df5044e21b4d"
        },
        {
            .input = "Fuvp JjZN iUGDPJIqW DzQxQJjB ObvoH ZDugpSXL pIdjXtp kbqiOz rvHuT XUTm IWw Brf EUVWaTkltp sCJwX tshziLFU mlZuJLsq vjPm IiZfewVQI wQvyztfvJj lGOrmlQm akLiCktOkr BrC ynSD vcysm Znw jxVCxjY wElvJZiz gxgCJlNG EwG oBWuEf wgokY AayCLsVNe yDmzLII HNdBmdtiK mBS cparX DJIFITvyMq MgfaDhRCPV RetElC OqdyoQ DTpxxXjO Qjv gwusbLCNZC ntoM ELJCuFV AUKVbXzxHe bifemxa FRnHPV zJBUldV EucQE bAICxxR LBxZMlV QsgVQKe RZVTA WAhJpAoav ckQURNYGam mWKoT VDg TEZBX EziulHe BmJhWbmekN KgbZp yKOIQ HyIMiMv YLdYg efAYRiQgd QoAE ibIEeIs FVkTAkb MPOGvOSGrq eqNNefhJi cRX xGRuKwjGb EksQ HSbLZiH SVezN mMhEoqS SYWQpa JAP jdNIcWp skQ CiMoMTTnnC VGMS EJdLX kueje Dclnh LTbJkQLoA CPwUUkCD kOu wmu YSNdyU ZBymImKCY XCKWSb LZapzo JlOoQ iaSyYZXn IxnEcP UJrSzjeG cIReTIK ukA qlMDIs kTykEReELU pRUsemyXA MfREl DgD EiapYmvrty tUPmVyFKHf bQJqkqTC gshxDbyuk SFQ CMe rYGMISCNf mLIfxkwwY ftLrg qILW AcoJKGsqfG uiE oWOLKJ lTrgbS kwMdus UkVBIrSo DqYC uYSj lWTJGnhvze lCPraBz BFfGFoDcK QkaBdJmw EjFMmg NFcWJBF MXIFUcoLTn uhqMWg LpawQe sDdOabpE DBVSl HDrdciLvOO jZhwsqZtZ OjuFX OowVlSLyAd BuKypkr YhqfuPT AcMR Bnc BdENXLUiNr gSjbtw rjnqZPf ZllUTO bXvsdjqE GiVIU iprPpJt tAaLATuGaS UXQwCUvBT UVLmhJqcb yOmnqgJC ZJg cFreJxg WlGWi eFVml jdYtB OwOwFtN osnlmMPLM wZrjH kqsY IgCBmpmK ehlighRYY JPIkaZLgb BzuJyzq xKNrtQnmJ VGbW eHIjAHrGRW oEkGNoeNK TlICRKFf WgECN",
            .expected_hash = "02c1ba8908cfb2fae227690a09a9e01975395d9724d95bee6a32159eb28f9985"
        },
        {
            .input = "TuNvIWrVLJ BMRF vsNJvHdy MwdVlRW CKasBo vAw EXQ UIjv AFvauP dXvKH qrlcRI qbRZ LHOKjY SoQ riuX tVtyuu sTBKNAVhz sjjHuZ wjDAKIGdQy ndANyeNj QRxAUc hsGNGNCe feHfBdWN jwzL FhTNItb EMYVYJCt TbarJUTgr OpdRcjdJeo RPUMOr yEkPtLmq GBnlU YxsHteQF WIhot ZgPGg JYtxjRa pXl HvrQmgi YbM VKBCbs fqMXp rIJwjGOtJ keln VGl DNuzhkiUq HuDyCJkJLs vBeLIqBkae vHz BENp fqpsneId IxSOrRsU SGVrwBxLi BTUZKrgBei YdHRnWK JlwpqCqQnm eLdV ioeFEArvf elAKXlXgb zZxO EpvW TWCtMLKR nbXBbyihGB aOuad udzMIAGNh uOEJH OYCmhSJmc HdGiFpTa uuwFNrrTXV EGAmo lFip JhbXrqsZq cQuD zVFMR eyQ sEMQYbR bVNmm crz TvDcS QOReohQMj TGc nvQw VyUHUa sFuVDzhhem UynlBYyuN joPS AWcSwKjEFa GjdjTpl fclnZWllo BzXnvbn CddWpU nbDmsvxid BtPCkj IAA xKSuQMOs iNAZBZd fvSI lCG cMQM qAClRmWmqQ qLwAVJk wRI qjcWwM RgVbdFX hKMy lpZfmDVHJz VDN xkg DbIPYMB JFRp sRxfw fHF qZa BFxDjN ANrU AyfBRG UCWDTl HYAOKiDZz aXApkSqQrg OqSzOE jNiDAHd hCOiYDwnmU YCIFi OtzDwIfn lXjqNbzb sNrFp qMffXs jCkVaHEoyJ sLjwWwcyPD mVHicSzUl LFvm ulC lPuyYlkQgE erOJal qPbIVHf ksDLjSw YLpfMeq JBJqHcyQx SxjeUnHI xRDeDtwraY UGEjqEDO BMGPhd DGM rDhIwWSK AivWXZqoAn PadrkKjzT eMMhMUlz JgM JqwkJMonGb JlxCuYRePm MRFrDC vqQzN gkT ChKpo JGOgHApePf",
            .expected_hash = "7c1694ac6fc2847826f1b789fd04241e3ecafc9646fcd834dd004ccef8fb4973"
        },
        {
            .input = "gJyfSxqiaK KvRsOofZ HzM mFUlF rWuwffGpyP xkHRwMJz aXpdcIpH EWlgr NcniTFSjkL DTPfCQen YVezwuMoXw EyANMl npW AueQygv OPniUmC LiPghuUl wLc CAaD zgFwJPGqyq uUye QaGjBChp uZFIauB XQyCIUBuBL qoGoi wEFACiW wotyun DGrEHepTM fmS mkgsUFb SkjmAswo MPGUp jzVHapgCPE vtSOTvxpy BTWg kUrPWJ kXS DTH BgoNF dIthfANR USi zXpeC qQJmxrTnJ GmdXXfWMW kTFFScrLmp xVi rfBD pibbHRvpT SUSGNs ouiwkncqy LxLNLHpKK xafrrn NFiSlTT udTTrG UbkfO GaNPLsAD fCCr ZQlGqB McQADNgLpM rAp yGAuZcE rIdBn OcADMKrt lKnZYEBTEb GIEJdT hzqWB tlhgiQg KKnB daKGgcLCJP wBBvuqnb FMgEruQwfk aSVc rHDbryR HhMT KoqCd vItNissrz WBbzDnp AUccxYBP DjLWQm bAY ImaatMoh QOwTlWKIzY VcWkwhE TEaGE BIcqBO PEKbngAkE QSyeZDVwCt csSmWWYJpr XxMhOb EiTnVrf GXedOVfaq lFMDxPKj HureWdEBW OUBjqbBJ hRIYuRC xqUDqbjcj CJJWkHZek bzsPnbNFD DAQgk lUhQgTBQ huJQfQEBj dgnI isxCMBtPg MCyNmbc eKOBeXBPz pHZ UekTpgLWh FkM dzOnmPNw FfLA TTffQ IGq PZlCkHdA OqaxWQKhY mXRnraq opASijs gdw oxI TJt zfzFu xXyRX eggrI rvimkTs idYG JdzWfsvNe mEg HuUrx Mgy ChF lTv Jqv gqL VhqgxiH QqmBN qIBrBbxw nATK YeNmnYe JJx wVLW NsuLv hcQyrOfoE TTL sjBojcjye UbUz WQB iNNHyE EdWLAR EhPnNFmkB VzcgdSlSj iVzsvm ndSh EsVALLN rTofL SczVaYtej Akspfk Hwhatyv adexs VUlnrjJl lte CEISEtIi uLPR LsZZa GLXgZl ECwe CaPzUblp qQZr esjEqgSdVy kba XXzkvP DxVTUp CSNftwmGFL miQAgxpS iwNPuGiedN tkeXwH IKiD yovM ABDpOtN hKCiFly fKSBA HvKkUiGkX Xnt fpKnKNuse LGJFIgNJ hXxjAGY etyAT jiu eMpbk xCVBqpUywU vskygdcmvj SAwOEKb cBMBtI srBhoJ gBdGhJBPA GJzRDqxGhy gZNWqGO BSX ZIvo ZQG XCqT",
            .expected_hash = "5ed49e1ee62e77443585cf8793b4b9891a42d7bf65c831245078fbe7e020462e"
        },
        {
            .input = "BSRqkopM iFAmqm Nar zgiUYQjoob Jso fUVGVEojD gTH OttighNM AFLd HpX mqpOAjAkN PySNUMZsT dIXn RewKdmp yoiLWLvLW Tmosv kRe EExawo hPe WBzPQmneE EqhLaJKpJc YjgsdqHWr XhsqbAP zJn BUULEjxDs PFn fUfwzgXszH kPo gLqW uWLzWk VsR CZfzeXYS uaWAmpMRpV IHZ AnPPbmHEe TeofIhY DTXZCX LBWYhqnX hqVyGG HhivOTSuLT vAnibuYb mrVqwtm ZHyRDRMt yXRacCQeP uebbcsIUV lGHvrZ FWQllMHAzz ziyWsgS WOCksQOyXn hbvqq TPBhLRF DUyTh TAJYjGSSrV qogHMobZ NttJWwFSLw rfrAyePjHw CQxVJav psmnOq vyUIHeDF rQLAAAiUvX xcICRat PDixNQV JtSRmI tuZyh RPQJobd WRNH LOs OUWt kyWHcWIh joBEdlvRee xRGTjUaSIB uaok GEdqQ GCZVnawgj DPTA sxjKicHgU pClI WiQTRYW QNJ SKL VhPe ZLz LJzQrQZl PlMta hKHuYJXJ RZRlLGgqCN EUapv NQyfsYLJg Cmlbvfy eNkqkadcZk",
            .expected_hash = "f7aa15d9ff687a9c1f3bd9db012d107c8e3d8b00572578c7615027ff82da0b6f"
        },
        {
            .input = "fELiUEKXc UoR BgRTc LiFuZPqU nNn Kfn wPCeA MPYF IMDoEam ETjMyDI uSIhwDsqTz AkQmRnX FeUukPp SINGfOZ HKPStLZlhZ shy VQN WObtWAL FXFNPtxLpt gQyqiyfUNC csnAo fQMFWCdqQg rlF cPaoXgdjY zgCScUOZE TgXuCxpcy xTJk bTFdfE hXVpR RWzGxwo mkICjHpM rkpbI gGrsGxV JWbo UyeXJfdI eSTvcVBB DmBdbp LZKKIvXs hbGGrdv MgtWYqNf OwOuDo asum UXHmwmx iAY ZeiEuTncE kRQpiPMCBz YvsGWLMkcP aGoKLPvO PeYWdgldW ggBGxqRITG IWipjlG UJfOVQO oZtnNRx epmfyDhUR UxtQSV kevu hbAH DQZAdd Otn GCpLfBhsZ LNZhDhQAvN bVBZP xoXUfKls qbDfK FOxqlXejPw uUC CYMvU YHZ jfxDTsqX sLxXr ssurSGfHB FzfEdzh ggkbxc uvdesyzcP lLqLuu HOXLnRbv SSd teDrd BKyp PwLouRle ysThsc DVq bKKuWQF fkngcTlSVg TUMIvbgjn NJUpnxRMEM cgAuVeUuyM NmGOxbdW dMJR MSVi YBXuN spj HcPzFWdU UxyOyLqkrH Npek gmff jNQUIau sue KuenBrI JelpPMmCer GZyfVYqebo XPzBoopVd RgENUa xPZEs yByXNM dvfghyy QiIUAhN xIss dWAg EvDlNXNEO lfvrD gQDTowycpw Rpztpnna fwr aVdgLJLl pTw WuCwN UdBrYGROP NhGLrC RzDbMhoKzY QbqTwlfm GsBPcCUB aaXKO DJmKAaZM maF HPkDlhi AQhnI JtcO KNQNbLRS UcXfzE LHMHEVWZ GaKi sTgZs oWBzcuIPr AyZI tksAS jCizxpwa QAVRsvxw fhxPPhKB",
            .expected_hash = "ddc763c9c331501c0ad377fa32e413747f04adc00a3dfccc38dbaed4738f97f9"
        },
        {
            .input = "oKeppcMxE IVZ iLdbw tzFK BlISXAPaZl JVdjCunhAY bMKmhM wAGTx IWqFH BvhgPzZkY wNX hwctxZ pVcdThH GHII rVlF rvlO phFJokvK Eea InU IfkV rQjiTvb LhCH JYQLhaaxy HOhix HrP rDSV txODNUvXT rqWsR BxnUuXUHx LLk RfibGFEX nwRIo hJsJbazPqz VAeCVwJYpC BWynms bIQJb MHHAxPQLl kwfInVzo Ksz ymEjYUyAIA Puokbsmxkf ebjpVVK mPPD iNO GMJupNeBn LOlGWjfglW DVzdqp xiWJ vsFDuZJ kra auei YRIpR IUvLsHT oGpp WIO AbPxSzqqyv rmJNw lLRFuvG DUTaZ RnP YSI wgUAzBHf MPvOD NgwChg CcVFYgNS VjeyPAge pxlNkLMW reGGAm SKn QyFDKh JRMnxP jAwUbxY BrdWKbsdBE vAKP pwAcPZ XpdE BMchszwhc ttVpmXqUML XZlC ouGfBPnGOM zLagrpGbs hQDdTmiav qfUMadoz AdFphJG xzrxW PySDIcYX UdLDIU uvh kPy GVS",
            .expected_hash = "8b08d1f13444a8e44cd036069418546f944821153f1a8ffa98f93078ad054215"
        },
        {
            .input = "GGN cjTa YmobuRcHML dbAyzWtdPv WkuaWP PbHfMB qFPIk NZaFo LqbGwinc ABJGW AaVOvz abptS ZcaRzrJdh TkVTbrT OmyxYKsNkI DvEO JyQNJL hJuFyl qwebRcsKJH VTKQx qAc jCFdFQm UqSrr EstsVss BQpk zPiuBUi Caj qLWyo HnA BNf dlxfIzfHIW TSBFbOz iCJBc bVowsAUNv vBZZEjCXrq TxHasEjDmD cYMAlyypV ZXgHgj CApUbCAQtb tGKm hFfGjFUAa LUrRzV frIRBuPCtY NzNn obU TxTI wheFM tMPJHsmytm EffkhXkbJ zwpBFhnAw JKOP Cyv YRDfdwcO hrsNuvwIbQ mnZgsdgLGW pGN kuGMJc yrrfQocLKm vMDH sVX jwFBwneTB pNY iTbLyZP UpxueR VpRWPDPFue xEb IIwjJK dQCoDzaN Vphgmh roaSrAWM SfXzsQUIxn UBocL sJYYbA PjBe PGCKPsy TvvOploj rnW ZZbeqRzOa AssOOV hSvB nAvRs zaXPle bCrgdBh yRQQhi Gab NtqWzh zOQ YSs grMeElkh OfDuKvW IaTyMML jYyYgTFUTQ hZHixa YDP etUhguFZa iyxlUK oDmtWom NNordGBRc uty VAkXnyi EGSaoWA UtDG aCIsQbtmFj TWxzlpgg lHvmsvglvm BfVqlhJO JLMd TRZ fasAhVgT LQZMAzxAk DaonMlVfs xyko HrdOEB meMWQc zGSyeHmIH eKtyqF cFreOEf YNYyNrAG pJzum MDQmzkoM WvT zxirbd qJpQf czK lgPjK TPqipmGP aGtjLm Kyo sfzC jBrkOn SZLrpm qJB zgcA xxIjj AKZ knywOmLz tMk Sxp GuSLfXQwb DIwznN VdDfJvbM XLJde mvaZieloDQ kVMTUXeCn CLR iezU lsBoelfUyH RpgMtT TKq NOb EVXV jdvZ rBkjlonkg MejyDJDSxN ZgGGl QPDho PtwezNyFi QlvfIT gfFAAoczPT BCi tHpnIJ azpqVUy bNyR",
            .expected_hash = "d9ba32d704a9174f3ddbedd1ac30a373ae54cc431bae7e5fb1c1e057ac413f14"
        }

    };

    bool res = true;

    for (const auto& val : le_test)
    {
        auto actual_hash = SHA256::generate(val.input);
        auto tmp_res = (actual_hash.unwrap() == convert(val.expected_hash));
        res &= tmp_res;
    }

    return res;
}

bool testAES()
{
    using namespace WinCppCrypt;
    using namespace WinCppCrypt::Util;

    bool res = true;

    {
        string_view msg = "hello world";
        string_view pwd = "Passw0rd";
        string_view aad = "v1.2";

        auto enc_res = AES256_GCM::encrypt(msg, pwd, aad);

        if (enc_res.hasError())
        {
            return false;
        }

        auto dec_res = AES256_GCM::decrypt(enc_res.unwrap(), pwd);

        if (dec_res.hasError())
        {
            return false;
        }

        auto original_msg = base64Encode(SHA256::generate(msg).unwrap());
        if (original_msg.hasError()) return false;

        auto decrypt_msg = base64Encode(SHA256::generate(dec_res.unwrap().plaintext).unwrap());
        if (decrypt_msg.hasError()) return false;

        res &= (original_msg.unwrap() == decrypt_msg.unwrap());
    }

    {
        const char* msg = "hello world but it's a const char*";
        const char* pwd = "1234567";
        const char* aad = "";

        auto enc_res = AES256_GCM::encrypt(msg, pwd, aad);

        if (enc_res.hasError())
        {
            return false;
        }

        auto dec_res = AES256_GCM::decrypt(enc_res.unwrap(), pwd);

        if (dec_res.hasError())
        {
            return false;
        }

        auto original_msg = base64Encode(SHA256::generate(msg).unwrap());
        if (original_msg.hasError()) return false;

        auto decrypt_msg = base64Encode(SHA256::generate(dec_res.unwrap().plaintext).unwrap());
        if (decrypt_msg.hasError()) return false;

        res &= (original_msg.unwrap() == decrypt_msg.unwrap());
    }

    {
        string msg = "hello world, but it's a good old std::string";
        string pwd = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        string aad = "v1.23";

        auto enc_res = AES256_GCM::encrypt(msg, pwd, aad);

        if (enc_res.hasError())
        {
            return false;
        }

        auto dec_res = AES256_GCM::decrypt(enc_res.unwrap(), pwd);

        if (dec_res.hasError())
        {
            return false;
        }

        auto original_msg = base64Encode(SHA256::generate(msg).unwrap());
        if (original_msg.hasError()) return false;

        auto decrypt_msg = base64Encode(SHA256::generate(dec_res.unwrap().plaintext).unwrap());
        if (decrypt_msg.hasError()) return false;

        res &= (original_msg.unwrap() == decrypt_msg.unwrap());
    }

    {
        auto msg = readEntireFile("C:\\Windows\\System32\\calc.exe");
        string_view pwd = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        string_view aad = "windows calc.exe";

        auto enc_res = AES256_GCM::encrypt(toSv(msg), pwd, aad);

        if (enc_res.hasError())
        {
            return false;
        }

        auto dec_res = AES256_GCM::decrypt(enc_res.unwrap(), pwd);

        if (dec_res.hasError())
        {
            return false;
        }

        auto original_msg = base64Encode(SHA256::generate(msg).unwrap());
        if (original_msg.hasError()) return false;

        auto decrypt_msg = base64Encode(SHA256::generate(dec_res.unwrap().plaintext).unwrap());
        if (decrypt_msg.hasError()) return false;

        res &= (original_msg.unwrap() == decrypt_msg.unwrap());
    }


    return res;
}

vector<string_view> split_string(
    string_view input,
    char delimiter = '\n'
)
{
    vector<string_view> result;
    size_t start = 0;
    size_t end = 0;

    while ((end = input.find(delimiter, start)) != std::string_view::npos)
    {
        auto substr = input.substr(start, end - start);
        result.emplace_back(substr);
        start = end + 1; // Skip the delimiter
    }

    // Add the last segment if there is anything left
    if (start < input.size())
    {
        auto substr = input.substr(start);
        result.emplace_back(substr);
    }

    return result;
}

bool testEncryptFile()
{
    using namespace WinCppCrypt;
    using namespace WinCppCrypt::Util;

    auto filename = "C:\\Windows\\System32\\calc.exe";
    auto encrypted_filename = "calc.exe.txt";
    auto decrypted_filename = "calc.exe";

    auto file_content = readEntireFile(filename);

    auto sha_original_file = SHA256::generate(file_content);

    auto pwd = "Passw0rd"sv;

    {
        auto enc_res = AES256_GCM::encrypt(file_content, pwd, "windows calculator"sv);

        if (enc_res.hasError())
        {
            cerr << "encryption failed: " << enc_res.error().what() << endl;
            return false;
        }

        if (not writeToFile(encrypted_filename, enc_res.unwrap()))
            return false;

    }

    //cout << endl;

    {
        auto encrypted_file_content = readEntireFile(encrypted_filename);

        auto base64_lines = split_string(toSv(encrypted_file_content));

        if (base64_lines.size() != 5)
        {
            cerr << "invalid number of lines in the encrypted file" << endl;
            return false;
        }

        auto ciphertext = base64Decode(base64_lines[0]).unwrap();
        auto nonce = base64Decode(base64_lines[1]).unwrap();
        auto salt = base64Decode(base64_lines[2]).unwrap();
        auto tag = base64Decode(base64_lines[3]).unwrap();
        auto aad = base64Decode(base64_lines[4]).unwrap();

        // cout << "[decrypt] ciphertext: " << toHexString(ciphertext) << endl;
        // cout << "[decrypt] nonce     : " << toHexString(nonce) << endl;
        // cout << "[decrypt] salt      : " << toHexString(salt) << endl;
        // cout << "[decrypt] tag       : " << toHexString(tag) << endl;

        auto dec_res = AES256_GCM::decrypt(
            ciphertext, pwd, nonce, tag, salt, aad
        );

        if (dec_res.hasError())
        {
            cerr << "decryption failed: " << dec_res.error().what() << endl;
            return false;
        }

        auto sha_decrypted_file = SHA256::generate(dec_res.unwrap().plaintext);

        if (sha_original_file.unwrap() != sha_decrypted_file.unwrap())
            return false;

        auto ofs = std::ofstream(decrypted_filename, std::ios::binary);

        if (not ofs.is_open())
        {
            cerr << "failed to open file for writing: " << decrypted_filename << endl;
            return false;
        }

        ofs.write(
            reinterpret_cast<const char*>(dec_res.unwrap().plaintext.data()),
            static_cast<std::streamsize>(dec_res.unwrap().plaintext.size())
        );

        ofs.flush(), ofs.close();
    }

    return true;
}

bool testUnusualEncryption()
{
    using WinCppCrypt::AES256_GCM::encrypt;
    using WinCppCrypt::AES256_GCM::decrypt;

    int nums[] = {1, 2, 3, 4, 5};

    auto res_encrypted = encrypt(nums, sizeof(nums), "password", {});
    if (res_encrypted.hasError()) return false;

    auto res_decrypted = decrypt(res_encrypted.unwrap(), "password");
    if (res_decrypted.hasError()) return false;

    auto nums2 = res_decrypted.unwrap().as<const int*>();

    return (memcmp(nums, nums2, sizeof(nums)) == 0);
}

bool testCompression()
{
    const char* data =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        ;
    auto data_size = strlen(data);

    auto compressed = WinCppCrypt::Util::compress(data, data_size);
    auto decompressed = WinCppCrypt::Util::decompress(compressed.data(), compressed.size());

    return (memcmp(data, decompressed.data(), data_size) == 0);
}

bool testCompressionFile()
{
    auto file_content = readEntireFile("C:\\Windows\\System32\\calc.exe");

    auto compressed = WinCppCrypt::Util::compress(file_content.data(), file_content.size());
    auto decompressed = WinCppCrypt::Util::decompress(compressed.data(), compressed.size());

    if (file_content.size() != decompressed.size())
        return false;

    return (memcmp(file_content.data(), decompressed.data(), decompressed.size()) == 0);
}

int main()
{
    // https://gchq.github.io/CyberChef

    try
    {
        cout << std::boolalpha;

        cout << "testEncodeDecodeBase64BinData: " << testEncodeDecodeBase64BinData() << "\n";
        cout << "testEncodeDecodeBase64:        " << testEncodeDecodeBase64() << "\n";
        cout << "testEncodeDecodeBase64File:    " << testEncodeDecodeBase64File() << "\n";
        cout << "testSHA256:                    " << testSHA256() << "\n";
        cout << "testAES:                       " << testAES() << "\n";
        cout << "testEncryptFile:               " << testEncryptFile() << "\n";
        cout << "testUnusualEncryption:         " << testUnusualEncryption() << "\n";
        cout << "testCompression:               " << testCompression() << endl;
        cout << "testCompressionFile:           " << testCompressionFile() << endl;

        return 0;
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[EXCEPTION]: " << ex.what() << endl;
    }

    return 1;
}
