#include <gtest/gtest.h>

#include "utils_math.h"
import math.PrimaryTests;

TEST(FermatTest, SmallPrimes) {
  const meow::math::primary::FermatTest f;
  for (const std::vector<BI> small_primes = {3, 5, 7, 11, 13, 17, 19, 23, 29,
                                             31};
       const auto& prime : small_primes) {
    EXPECT_TRUE(f.isPrimary(prime, 0.9998));
  }
}

TEST(FermatTest, SmallComposites) {
  const meow::math::primary::FermatTest f;
  for (const std::vector<BI> composites = {4, 6, 8, 9, 10, 12, 14, 15, 16, 18,
                                           20, 21, 22, 24, 25};
       const auto& composite : composites) {
    EXPECT_FALSE(f.isPrimary(composite, 0.9999998)) << composite;
  }
}

TEST(FermatTest, MediumPrimes) {
  const meow::math::primary::FermatTest f;
  for (const std::vector<BI> primes = {101, 103, 107, 109, 113, 127, 131, 137,
                                       139, 149};
       const auto& prime : primes) {
    EXPECT_TRUE(f.isPrimary(prime, 0.9998));
  }
}

TEST(FermatTest, MediumComposites) {
  const meow::math::primary::FermatTest f;
  std::vector<BI> composites = {100, 102, 104, 105, 106,
                                108, 110, 111, 112, 114};
  for (const auto& composite : composites) {
    EXPECT_FALSE(f.isPrimary(composite, 0.9998));
  }
}

TEST(FermatTest, LargePrimes) {
  const meow::math::primary::FermatTest f;
  for (const BI& prime :
       {BI("8683317618811886495518194401279999999"),
        BI("263130836933693530167218012159999999"),
        BI("265252859812191058636308479999999"),
        BI("10888869450418352160768000001"),
        BI("2855425422282796139015635661021640083261642386447028891992474566022"
           "8440039060065387595457150553984323975451391589615029787839937705607"
           "1435169747221107988791198200988477531339214282772016059009904586686"
           "2549890848157354224804090223442975883525260043838906326161240763173"
           "8741688114859248618836187390417578314569601691957439076559828018859"
           "9035578448591077683677175520434074287726578006266759615970759521327"
           "8285556627816783856915818444364448125115624281367424904593632128101"
           "8027609608811140100337757036354572512092407364692157679714619938761"
           "9296560302680261790118132925012323046444438622308877924609373773012"
           "4816816724244936744744885377701557830068808526481615130671448147902"
           "8836666406225727466527578712737464923109637500117090189078626332461"
           "9578795731425693805073056119677580338084333381987500902968831935913"
           "0952698213111413223933564901784887289822881562826008138312961436638"
           "4594543114404375382154287127774560644785856415921332844358020642271"
           "4694913091762716447041689678070096773590429808909616750452927258000"
           "8435003448316282970899027286499819943876472345742762637296948483047"
           "5091717418618113068851879274862261229334136892805663438446664632657"
           "2476167275660839105650528975713899320211121495795311427946254553305"
           "3870678210676017687509778661004600146021384084480212250536890547937"
           "42003095722096732954750721718115531871310231057902608580607")}) {
    EXPECT_TRUE(f.isPrimary(prime, 0.9998)) << prime;
  }
}

TEST(FermatTest, LargeComposites) {
  const meow::math::primary::FermatTest f;
  std::vector<BI> composites = {
      BI("115792089237316195423570985008687907853269984665640564039457584007913"
         "129639937"),
      BI("9999999999999999999999999999999999999999"),
      BI("8727963568087712425891397479476727340041448"),
      BI("1606938044258990275541962092341162602522202993782792835301377"),
      BI("10000001")};
  for (const auto& composite : composites) {
    EXPECT_FALSE(f.isPrimary(composite, 0.9998)) << composite;
  }
}

TEST(FermatTest, EdgeCases) {
  const meow::math::primary::FermatTest f;
  ASSERT_THROW(f.isPrimary(BI(0), 0.9998), std::runtime_error);
  ASSERT_THROW(f.isPrimary(BI(1), 0.9998), std::runtime_error);
  EXPECT_TRUE(f.isPrimary(BI(2), 0.9998));
}

TEST(FermatTest, RoundCountCalculation) {
  const meow::math::primary::FermatTest f;
  EXPECT_GT(f.roundCnt(0.9998), 0);
  EXPECT_GE(f.roundCnt(0.9999), f.roundCnt(0.9998));
}