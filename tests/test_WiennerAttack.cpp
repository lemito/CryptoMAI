#include <gtest/gtest.h>

#include <print>

#include "utils_math.h"
import cypher.BadRSA;
import cypher.RSA.WiennerAttack;

TEST(ContinuedFraction, Basic0) {
  const BI a = 649;
  const BI b = 200;
  const std::vector<BI> expect = {3, 4, 12, 4};
  const auto res = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::calcCoeffs({a, b});
  ASSERT_TRUE(res == expect);
}

TEST(ContinuedFraction, Basic1) {
  const BI a = 9;
  const BI b = 4;
  const std::vector<BI> expect = {2, 4};
  const auto res = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::calcCoeffs({a, b});
  ASSERT_TRUE(res == expect);
}

TEST(ContinuedFraction, Basic2) {
  const BI a = 4;
  const BI b = 9;
  const std::vector<BI> expect = {0, 2, 4};
  const auto res = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::calcCoeffs({a, b});
  ASSERT_TRUE(res == expect);
}

TEST(Convergents, Basic) {
  const BI a = 15;
  const BI b = 47;
  const auto res = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::calcCoeffs({a, b});
  for (const auto conv = meow::cypher::RSA::attack::WiennerAttackService::
           ContinuedFraction::convergentsCF(res);
       auto& re : conv) {
    std::cout << re << std::endl;
  }
}

TEST(Convergents, Basic0) {
  const BI a = 13;
  const BI b = 17;
  const std::vector<meow::cypher::RSA::attack::WiennerAttackService::Fraction>
      expect = {{0, 1}, {1, 1}, {3, 4}, {13, 17}};
  const auto res = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::calcCoeffs({a, b});
  const auto conv = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::convergentsCF(res);
  for (const auto& elem : conv) {
    std::cout << elem << std::endl;
  }
  ASSERT_TRUE(conv == expect);
}

TEST(Convergents, Basic1) {
  const BI a = 17993;
  const BI b = 90581;
  const std::vector<meow::cypher::RSA::attack::WiennerAttackService::Fraction>
      expect = {
          {0, 1},      {1, 5},       {29, 146},     {117, 589},     {146, 735},
          {555, 2794}, {1256, 6323}, {5579, 28086}, {17993, 90581},
      };
  const auto res = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::calcCoeffs({a, b});
  const auto conv = meow::cypher::RSA::attack::WiennerAttackService::
      ContinuedFraction::convergentsCF(res);
  for (const auto& elem : conv) {
    std::cout << elem << std::endl;
  }
  ASSERT_TRUE(conv == expect);
}

TEST(FindD, Simple) {
  const BI e = 17993;
  const BI N = 90581;
  const BI expected_d = 5;

  const auto [decrypt_exp, phi, convergents] =
      meow::cypher::RSA::BadRSA::BadRSAService::hack(e, N);
  ASSERT_TRUE(decrypt_exp == expected_d);
  std::cout << phi << std::endl;
  for (auto& elem : convergents) {
    std::cout << elem << std::endl;
  }
}

TEST(FindD, Simple0) {
  const BI e = 1073780833;
  const BI N = 1220275921;
  const BI expected_d = 25;

  const auto [decrypt_exp, phi, convergents] =
      meow::cypher::RSA::BadRSA::BadRSAService::hack(e, N);
  ASSERT_TRUE(decrypt_exp == expected_d);
  std::cout << phi << std::endl;
  for (auto& elem : convergents) {
    std::cout << elem << std::endl;
  }
}

TEST(FindD, Simple1) {
  const BI e = 1779399043;
  const BI N = 2796304957;
  const BI expected_d = 11;

  const auto [decrypt_exp, phi, convergents] =
      meow::cypher::RSA::BadRSA::BadRSAService::hack(e, N);
  ASSERT_TRUE(decrypt_exp == expected_d);

  std::cout << phi << std::endl;
  for (auto& elem : convergents) {
    std::cout << elem << std::endl;
  }
}

TEST(GoodKeys, Simple0) {
  const auto e =
      BI("430984319905058242085660358541083211337657674754398255655169021356732"
         "124991746979842720136798371648615735545103050304715525473895250640417"
         "426492286566827518166664359529521022397084553062469937349121583522597"
         "585653684052957671762800930735814507856267678887491979225357287147795"
         "429995647864382454789710971602896291890049638750624369252374727589777"
         "742603055639697417003761913504914773100713816789476519864236466782037"
         "782386002144297077885258320992437187996178097623922259671231469560043"
         "703181298011432335827937262256966715635166924645338586687848916600878"
         "828255054777549262154916691509429060056388477425702729966988922147769"
         "111111084551758347140575176912855166914669817249033563417429539573896"
         "972278468169093068893991659733540568379596356412780090558760233985373"
         "613140849408711278667348532345632460680623564777672856036314185086462"
         "323866389463833106938923261659412962417849237299388536190228919264032"
         "914980957322033543997030436192521754417014484417786653251502611267421"
         "334525403301247936093203959549874447423832523180787821194488823671782"
         "040944069825677627862413564391917461550211369413308922073696540699136"
         "709925454649696753166349812648898661380133847548858093820871310584616"
         "768465975773915001383848501003727436676259926527897750371093");
  const auto N =
      BI("590537812962554368693613064648855982348253843536907080507246530548486"
         "212408516343604946519945029473912040922269473505180584228619106627400"
         "235293392310738638179579845884682826545785252137334713452145929735856"
         "674899243517172945469706594388849606586672424083723877868370375664403"
         "487950954830417881131946303273374115358455918967524293469904401555051"
         "979537285260062297364132450999193250468769610426702697175678846568142"
         "379529392563084348893435507206490697001163523251735627072830184532028"
         "811857856945946411907877146744724013781045955621829047698245716696404"
         "288337542387374221502881092829491275230330106807776645893518868412727"
         "759043380331126155721412640622896145330646403159940144224053049767555"
         "220876150629110852029678064479363272450904917587383785320872646600607"
         "642968073234920273559911810364500398798275828128536043245175603972592"
         "599258500359688863619853999120249985988555983214216608402886384136576"
         "840266931503092841995327158242957773351552115499598525331827058706924"
         "863697354278318761436552779996617164923250408959912016504773563200956"
         "827045484635741733526771648402602792245590797152485016311428192536027"
         "933642200249903491401647794010694246092401473368768650339436571285217"
         "009231289163066249688504373012319831807579082467434547721371");
  ASSERT_THROW(meow::cypher::RSA::BadRSA::BadRSAService::hack(e, N),
               meow::cypher::RSA::attack::hack_err);
}
// TEST(BadRSA, Simple) {
//   const auto some_msg = BI("74123657855656565836662666");
//   const meow::cypher::RSA::BadRSA::BadRSAService service{
//       meow::cypher::RSA::BadRSA::BadRSAService::KeyGen::PrimaryTests::
//           MillerRabinTest,
//       0.98, 256};
//   const auto res = service.encrypt(some_msg);
//   const auto res2 = service.decrypt(res);
//   ASSERT_TRUE(some_msg == res2);
// }
//
// TEST(BadRSA, Hack) {
//   const auto some_msg = BI("74123657855656565836662666");
//   const meow::cypher::RSA::BadRSA::BadRSAService service{
//       meow::cypher::RSA::BadRSA::BadRSAService::KeyGen::PrimaryTests::
//           MillerRabinTest,
//       0.98, 2048};
//   const auto res = service.encrypt(some_msg);
//   const auto res2 = service.decrypt(res);
//   std::cout << "e= " << service.public_key_.encrypt_word
//             << "\nN= " << service.public_key_.N << std::endl;
//   const auto hackRes =
//       service.hack(service.public_key_.encrypt_word, service.public_key_.N);
//   std::cout << hackRes.decrypt_exp << std::endl;
//   for (auto& elem : hackRes.convergents) {
//     std::cout << elem << std::endl;
//   }
// }

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}