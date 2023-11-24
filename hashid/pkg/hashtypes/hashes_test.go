package hashtypes

import (
	"os"
	"testing"
)

var hashid *Hashes

type testCases struct {
	name   string
	hashes []string
	want   string
}

var tests = []testCases{
	{
		name: "1PasswordAgileKeychain",
		hashes: []string{
			"1000:9e55bd14cb90f5e1:99a89704bc67d6921ab393ca46ee7973e0d5227938a6d669cdc920ad7ae857eb4163dcccf6770190f80d3478c62904827c59d5c97f2a0f16ea9f3aee6992d921b0244617e309a8283c91a21c524561923658dee0d4d304465bac5f766ef26b02534e44a7d1506088f95f9610dbfaf1ace6cf4368921a28367415e7d76938faf3d7a27750eaf74c1855a671ad7b2e4fdb30734022c37565ec8e30681db367ad8be49ce3927232ccd8e0d8a4e726acf88fa8dedf32c24ba771a3f5eb2aae13180ca4c29e2b7fccec4bc4e4d32eb01c6b12405a5a2b8d3aea44d7745be76bec9068ec2dd13d227b3bdb4962143dfc74496e00e228465b6f214428243b3fca652c3f8661915fcae0a5db919f87f9e9202ae7e0a4080849dc5003d7618585746ec637dd9d17cb97be9f2eb550fd539d51ae4a6d07c63903c83c780bb8520ba6462bae6f1dec54fee0707e82345b39c46befd3eefe0c33e30adb13cafe7dc4f18b53bee60dccf92c80cfae1671f9e3c6b0cf0ed278bfbdbd69ee910130554d8348287c9372e0f437194018355f71b5236114f03b7a58036b85ac8f089b7eaa72ab8997c9e26c40a095014b64d5c3b9221e59f5b9e7dd1d730420875b73a6ad841f68c2004e5622400905000c977edb625d54c6a42cecfc9009bb4489ebb4d1e339e0d014a972364e378441c761aad8c8929f753917b9a1e1a316831cb9d6ba92354a47202b78ab2f42f2c99284c12d3e212ebf8ea8ec683aeb62c0e5d588cca9cc08aac3ead97831bfa1f698dac9f857e8cdd9ec4b15cffb5900f2f951c657f831689ac6199033b13cecf4b29d84fb06f422acd3db566d7ec6b664325c4331ff35963553c26e94af6eb5b36fe79f14bf3a30f4964ded7991ef5d859ebbb0e98c821b21f9620fca9086f9b3b2a7ad8360c4a635c481f1ef4990f7f0ec4fde37723b4639ee633bdb32be6bf31298a4574381d95831d65b3e8e6352b1207a684401a0f3fcff65e0ed1e6ec714c07526896468daeb056cbe49d82b87092e53ac40cfba049983ce8923bed2de773d15a5e87a88041f72c34d8c0436f95368ec73abfdd1d21897f649e1de9e7198e9db342c93b3b8b0d3af6c4867d63fed394674e5b02c92b7698d5457d2cca773abaad69c4a0a36e468a40d14b8bd73fa1d9074c8881158e10e4243045ab254775bda1e7e89a68005d91bb67044ed407f221d1028d034aedcfea3b527725607bd5c3f880557cfc6c2c0bb3361ae131261b8a5ebf3b53521fdd731ec2413c61bc78a1ab7f78057abd1c5459250fba0e0d57c1f4ebd3e1871ce0f5bfd44d2790d946936eef03e14e81f33f5484eec0a76910c253bf2777232be1a3593678f27225b035999d9ffb675685457b48928db1f1be6c3f206ad2efc764f8ba77a38b439f1e28318a1b077fe0c9e36fa6ed0df0f052d9aadd56b1514b5d01a44161fcea20f6326fab1ee3d7f79",
		},
		want: "1Password(Agile Keychain)",
	},
	{
		name: "1PasswordCloudKeychain",
		hashes: []string{
			"92407e964bb9a368e86bcd52273e3f6b86181ab1204a9ed709bbe97667e7f67c:c1b981dd8e36340daf420badbfe38ca9:40000:991a0942a91889409a70b6622caf779a00ba472617477883394141bd6e23e38d8e2f5a69f5b30aa9dc28ebf6ecedcb679224e29af1123889a947576806536b831cc1d159a6d9135194671719adf86324ce6c6cbc64069c4210e748dde5400f7da738016a6b3c35c843f740008b0282581b52ea91d46a9600bfa8b79270d1ce8e4326f9fc9afa97082096eaf0ce1270eb030f53e98e3654d6fd38a313777b182051d95d582f67675628202dab60f120d4146250fa9ade4d0112aa873b5eb56425380e7b1220f6284ed1fa7d913a595aedfc0159ba2c95719d3c33646372098dc49037018885ed5d79e3479fee47fbe69076ea94852672f04f10e63fe3f53366fd61f7afd41831150cf24a49e837d72d656a1906943117252ab1f3889261ce09c3d832a4d583cfc82a049cee99cf62d4ec",
		},
		want: "1Password(Cloud Keychain)",
	},
	{
		name: "3DESPT$SaltKey$Pass)",
		hashes: []string{
			"37387ff8d8dafe15:8152001061460743",
		},
		want: "3DES (PT = $salt, key = $pass)",
	},
	{
		name: "7Zip",
		hashes: []string{
			"$7z$0$19$0$salt$8$f6196259a7326e3f0000000000000000$185065650$112$98$f3bc2a88062c419a25acd40c0c2d75421cf23263f69c51b13f9b1aada41a8a09f9adeae45d67c60b56aad338f20c0dcc5eb811c7a61128ee0746f922cdb9c59096869f341c7a9cb1ac7bb7d771f546b82cf4e6f11a5ecd4b61751e4d8de66dd6e2dfb5b7d1022d2211e2d66ea1703f96",
		},
		want: "7-Zip",
	},
	{
		name: "AESCryptSHA256",
		hashes: []string{
			"$aescrypt$1*efc648908ca7ec727f37f3316dfd885c*eff5c87a35545406a57b56de57bd0554*3a66401271aec08cbd10cf2070332214093a33f36bd0dced4a4bb09fab817184*6a3c49fea0cafb19190dc4bdadb787e73b1df244c51780beef912598bd3bdf7e",
		},
		want: "AES Crypt (SHA256)",
	},
	{
		name: "AES128ECBNOKDFPT$SaltKey$Pass)",
		hashes: []string{
			"e7a32f3210455cc044f26117c4612aab:86046627772965328523223752173724",
		},
		want: "AES-128-ECB NOKDF (PT = $salt, key = $pass)",
	},
	{
		name: "AES192ECBNOKDFPT$SaltKey$Pass)",
		hashes: []string{
			"2995e91b798ef51232a91579edb1d176:49869364034411376791729962721320",
		},
		want: "AES-192-ECB NOKDF (PT = $salt, key = $pass)",
	},
	{
		name: "AES256ECBNOKDFPT$SaltKey$Pass)",
		hashes: []string{
			"264a4248c9522cb74d33fe26cb596895:61270210011294880287232432636227",
		},
		want: "AES-256-ECB NOKDF (PT = $salt, key = $pass)",
	},
	{
		name: "AIXSMD5",
		hashes: []string{
			"{smd5}a5/yTL/u$VfvgyHx1xUlXZYBocQpQY0",
		},
		want: "AIX {smd5}",
	},
	{
		name: "AIXSSHA1",
		hashes: []string{
			"{ssha1}06$bJbkFGJAB30L2e23$dCESGOsP7jaIIAJ1QAcmaGeG.kr",
		},
		want: "AIX {ssha1}",
	},
	{
		name: "AIXSSHA256",
		hashes: []string{
			"{ssha256}06$aJckFGJAB30LTe10$ohUsB7LBPlgclE3hJg9x042DLJvQyxVCX.nZZLEz.g2",
		},
		want: "AIX {ssha256}",
	},
	{
		name: "AIXSSHA512",
		hashes: []string{
			"{ssha512}06$bJbkFGJAB30L2e23$bXiXjyH5YGIyoWWmEVwq67nCU5t7GLy9HkCzrodRCQCx3r9VvG98o7O3V0r9cVrX3LPPGuHqT5LLn0oGCuI1..",
		},
		want: "AIX {ssha512}",
	},
	{
		name: "Adler32",
		hashes: []string{
			"08950272",
		},
		want: "Adler-32",
	},
	{
		name: "AndroidBackup",
		hashes: []string{
			"$ab$5*0*10000*b8900e4885ff9cad8f01ee1957a43bd633fea12491440514ae27aa83f2f5c006ec7e7fa0bce040add619919b4eb60608304b7d571a2ed87fd58c9ad6bc5fcf4c*7d254d93e16be9312fb1ccbfc6265c40cb0c5eab7b605a95a116e2383fb1cf12b688223f96221dcd2bf5410d4ca6f90e0789ee00157fa91658b42665d6b6844c*fc9f6be604d1c59ac32664ec2c5b9b30*00c4972149af3adcc235899e9d20611ea6e8de2212afcb9fcfefde7e35b691c2d0994eb47e4f9a260526ba47f4caea71af9c7fadcd5685d50126276f6acdd59966528b13ccc26036a0eaba2f2451aa64b05766d0edd03c988dcf87e2a9eec52d",
		},
		want: "Android Backup",
	},
	{
		name: "AndroidFDESamsungDEK",
		hashes: []string{
			"38421854118412625768408160477112384218541184126257684081604771129b6258eb22fc8b9d08e04e6450f72b98725d7d4fcad6fb6aec4ac2a79d0c6ff738421854118412625768408160477112",
		},
		want: "Android FDE (Samsung DEK)",
	},
	{
		name: "AndroidFDE43",
		hashes: []string{
			"$fde$16$ca56e82e7b5a9c2fc1e3b5a7d671c2f9$16$7c124af19ac913be0fc137b75a34b20d$eac806ae7277c8d48243d52a8644fa57a817317bd3457f94dca727964cbc27c88296954f289597a9de3314a4e9d9f28dce70cf9ce3e1c3c0c6fc041687a0ad3cb333d4449bc9da8fcc7d5f85948a7ac3bc6d34f505e9d0d91da4396e35840bde3465ad11c5086c89ee6db68d65e47a2e5413f272caa01e02224e5ff3dc3bed3953a702e85e964e562e62f5c97a2df6c47547bfb5aeeb329ff8f9c9666724d399043fe970c8b282b45e93d008333f3b4edd5eb147bd023ed18ac1f9f75a6cd33444b507694c64e1e98a964b48c0a77276e9930250d01801813c235169a7b1952891c63ce0d462abc688bd96c0337174695a957858b4c9fd277d04abe8a0c2c5def4b352ba29410f8dbec91bcb2ca2b8faf26d44f02340b3373bc94e7487ce014e6adfbf7edfdd2057225f8aeb324c9d1be877c6ae4211ae387e07bf2a056984d2ed2815149b3e9cf9fbfae852f7dd5906c2b86e7910c0d7755ef5bcc39f0e135bf546c839693dc4af3e50b8382c7c8c754d4ee218fa85d70ee0a5707a9f827209a7ddb6c2fb9431a61c9775112cc88aa2a34f97c2f53dfce082aa0758917269a5fc30049ceab67d3efd721fee021ffca979f839b4f052e27f5c382c0dd5c02fd39fbc9b26e04bf9e051d1923eff9a7cde3244902bb8538b1b9f11631def5aad7c21d2113bcdc989b771ff6bf220f94354034dd417510117b55a669e969fc3bc6c5dcd4741b8313bf7d999dc94d4949f27eec0cd06f906c17a80d09f583a5dd601854832673b78d125a2c5ad0352932be7b93c611fee8c6049670442d8c532674f3d21d45d3d009211d2a9e6568252ac4682982172cb43e7c6b05e85851787ad90e25b77cce3f7968d455f92653a1d3790bc50e5f6e1f743ac47275ffa8e81bbe832a8d7d78d5d5a7c73f95703aebb355849ae566492093bd9cb51070f39c69bb4e22b99cc0e60e96d048385bb69f1c44a3b79547fbc19a873a632f43f05fa2d8a6f9155e59d153e2851b739c42444018b8c4e09a93be43570834667d0b5a5d2a53b1572dab3e750b3f9e641e303559bace06612fbd451a5e822201442828e79168c567a85d8c024cd8ce32bf650105b1af98cc5428675f4f4bbede37a0ef98d1533a8a6dcb27d87a2b799f18706f4677edaa0411becac4c591ede83993aedba660d1dd67f6c4a5c141ad3e6e0c77730cb0ecbf4f4bd8ef6067e05ca3bc563d9e1554a893fea0050bdd1733c883f533f87eac39cceee0ccf817fc1f19bcfdd13e9f241b89bfb149b509e9a0747658438536b6705514cc6d6bb3c64c903e4710435d8bebc35297d1ebbdff8074b203f37d1910d8b4637e4d3dab997f4aa378a7a67c79e698a11e83d0d7e759d0e7969c4f5408168b282fe28d3279ec1d4cc6f85a0f8e5d01f21c7508a69773c44167ff8d467d0801f9ec54f9ee2496d4e7e470214abc1ca11355bb18cd23273aac6b05b47f9e301b42b137a2455758c24e2716dcd2e55bbeb780f592e664e7392bf6eccb80959f24c8800816c84f2575e82e1f3559c33a5be7a3a0c843c2989f486b113d5eeada007caf6b5a0f6d71e2f5c09a4def57c7057168051868317a9ec790d570d76a0d21a45ad951c475db5a66101475871147c5a5907ec4e6b14128ed6695bb73c1c97952e96826eeb6003aa13462093e4afc209627241f03b0247e110fbab983640423b7cdf112e01579fed68c80ac7df7449d9d2114b9ae5539c03c2037be45c5f74e7357b25c6a24b7bd503864437147e50d7ac4ccc4bbd0cabecdc6bac60a362285fe450e2c2d0a446578c8880dc957e6e8061e691b83eb8062d1aad476e0c7b25e4d5454f1288686eb525f37fe649637b235b7828366b0219a9c63d6ddbb696dc3585a2ebfbd5f5e4c170d6784ab9993e15142535e194d2bee3dc9477ef8b8e1b07605e0c04f49edf6d42be3a9dabbc592dde78ce8b7dd9684bfcf4ca2f5a44b1872abe18fb6fa67a79390f273a9d12f9269389629456d71b9e7ed3447462269a849ce83e1893f253c832537f850b1acce5b11d2ba6b7c2f99e8e7c8085f390c21f69e1ce4bbf85b4e1ad86c0d6706432766978076f4cada9ca6f28d395d9cc5e74b2a6b46eb9d1de79eeecff7dc97ec2a8d8870e3894e1e4e26ccb98dd2f88c0229bbd3152fa149f0cc132561f",
		},
		want: "Android FDE <= 4.3",
	},
	{
		name: "AnsibleVault",
		hashes: []string{
			"$ansible$0*0*6b761adc6faeb0cc0bf197d3d4a4a7d3f1682e4b169cae8fa6b459b3214ed41e*426d313c5809d4a80a4b9bc7d4823070*d8bad190c7fbc7c3cb1c60a27abfb0ff59d6fb73178681c7454d94a0f56a4360",
		},
		want: "Ansible Vault",
	},
	{
		name: "ApacheAPR1MD5",
		hashes: []string{
			"$apr1$71850310$gh9m4xcAn3MGxogwX/ztb.",
		},
		want: "Apache $apr1$ MD5, md5apr1, MD5 (APR)",
	},
	{
		name: "AppleFileSystemAPFS",
		hashes: []string{
			"$fvde$2$16$58778104701476542047675521040224$20000$39602e86b7cea4a34f4ff69ff6ed706d68954ee474de1d2a9f6a6f2d24d172001e484c1d4eaa237d",
		},
		want: "Apple File System (APFS)",
	},
	{
		name: "AppleKeychain",
		hashes: []string{
			"$keychain$*74cd1efd49e54a8fdc8750288801e09fa26a33b1*66001ad4e0498dc7*5a084b7314971b728cb551ac40b2e50b7b5bd8b8496b902efe7af07538863a45394ead8399ec581681f7416003c49cc7",
		},
		want: "Apple Keychain",
	},
	{
		name: "AppleSecureNotes",
		hashes: []string{
			"$ASN$*1*20000*80771171105233481004850004085037*d04b17af7f6b184346aad3efefe8bec0987ee73418291a41",
		},
		want: "Apple Secure Notes",
	},
	{
		name: "AppleiWork",
		hashes: []string{
			"$iwork$2$1$1$4000$b31b7320d1e7a5ee$01f54d6f9e5090eb16fef2b05f8242bc$69561c985268326b7353fb22c3685a378341127557bd2bbea1bd10afb31f2127344707b662a2c29480c32b8b93dea0538327f604e5aa8733be83af25f370f7ac",
		},
		want: "Apple iWork",
	},
	{
		name: "ArubaOS",
		hashes: []string{
			"5387280701327dc2162bdeb451d5a465af6d13eff9276efeba",
		},
		want: "ArubaOS",
	},
	{
		name: "AtlassianPBKDF2HMACSHA1",
		hashes: []string{
			"{PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa",
		},
		want: "Atlassian (PBKDF2-HMAC-SHA1)",
	},
	{
		name: "AuthMeSHA256",
		hashes: []string{
			"$SHA$7218532375810603$bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824",
		},
		want: "AuthMe sha256",
	},
	{
		name: "AxCrypt1",
		hashes: []string{
			"$axcrypt$*1*10000*aaf4a5b4a7185551fea2585ed69fe246*45c616e901e48c6cac7ff14e8cd99113393be259c595325e",
		},
		want: "AxCrypt 1",
	},
	{
		name: "AxCrypt1InMemorySHA1",
		hashes: []string{
			"$axcrypt_sha1$b89eaac7e61417341b710b727768294d0e6a277b",
		},
		want: "AxCrypt 1 in-memory SHA1",
	},
	{
		name: "AxCrypt2AES128",
		hashes: []string{
			"$axcrypt$*2*10000*6d44c6d19076bce9920c5fb76b246c161926ce65abb93ec2003919d78898aadd5bc6e5754201ff25d681ad89fa2861d20ef7c3fd7bde051909dfef8adcb50491*68f78a1b80291a42b2a117d6209d3eb3541a8d47ed6b970b2b8294b2bc78347fc2b494a0599f8cba6d45e88fd8fbc5b4dd7e888f6c9543e679489de132167222e130d5925278693ad8599284705fdf99360b2199ed0005be05867b9b7aa6bb4be76f5f979819eb27cf590a47d81830575b2af09dda756360c844b89c7dcec099cfdd27d2d0c95d24f143405f303e4843*1000*debdeb8ea7b9800b01855de09b105fdb8840efc1f67dc742283d13a5570165f8",
		},
		want: "AxCrypt 2 AES-128",
	},
	{
		name: "AxCrypt2AES256",
		hashes: []string{
			"$axcrypt$*2*10000*79bea2d51670484a065241c52613b41a33bf56d2dda9993770e8b0188e3bbf881bea6552a2986c70dc97240b0f91df2eecfa2c7044998041b3fbd58369cfef79*4982f7a860d4e92079bc677c1f89304aa3a2d9ab8c81efaff6c78a12e2873a3a23e6ae6e23a7144248446d8b44e3e82b19a307b2105570a39e1a7bed70b77bbf6b3e85371fe5bb52d1d4c7fcb3d755b308796ab7c4ff270c9217f05477aff5e8e94e5e8af1fba3ce069ce6fc94ae7aeebcb3da270cab672e95c8042a848cefc70bde7201b52cba9a8a0615ac70315792*1000*e2438859e86f7b4076b0ee4044ad5d17c3bb1f5a05fcb1af28ed7326cf71ced2",
		},
		want: "AxCrypt 2 AES-256",
	},
	{
		name: "BLAKE2b512",
		hashes: []string{
			"$BLAKE2$296c269e70ac5f0095e6fb47693480f0f7b97ccd0307f5c3bfa4df8f5ca5c9308a0e7108e80a0a9c0ebb715e8b7109b072046c6cd5e155b4cfd2f27216283b1e",
		},
		want: "BLAKE2b-512",
	},
	{
		name: "BLAKE2b512PassSalt",
		hashes: []string{
			"$BLAKE2$41fcd44c789c735c08b43a871b81c8f617ca43918d38aee6cf8291c58a0b00a03115857425e5ff6f044be7a5bec8536b52d6c9992e21cd43cdca8a55bbf1f5c1:1033",
		},
		want: "BLAKE2b-512($pass.$salt)",
	},
	{
		name: "BLAKE2b512SaltPass",
		hashes: []string{
			"$BLAKE2$f0325fdfc3f82a014935442f7adbc069d4636d67276a85b09f8de368f122cf5195a0b780d7fee709fbf1dcd02ddcb581df84508cf1fb0f3393af1be0565491c6:3301",
		},
		want: "BLAKE2b-512($salt.$pass)",
	},
	{
		name: "BSDiCryptExtendedDES",
		hashes: []string{
			"_9G..8147mpcfKT8g0U.",
		},
		want: "BSDi Crypt, Extended DES",
	},
	{
		name: "BestCryptv3VolumeEncryption",
		hashes: []string{
			"$bcve$3$08$234b8182cee7098b$35c12ef76a1e88175c4c222da3558310a0075bc7a06ecf46746d149c02a81fb8a97637d1103d2e13ddd5deaf982889594b18c12d7ca18a54875c5da4a47f90ae615ab94b8e3ed9e3c793d872a1b5ac35cfdb66c221d6d0853e9ff2e0f4435b43",
		},
		want: "BestCrypt v3 Volume Encryption",
	},
	{
		name: "BitLocker",
		hashes: []string{
			"$bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$3a33a8eaff5e6f81d907b591$60$316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6145bf8561ea86f52d3592059fb",
		},
		want: "BitLocker",
	},
	{
		name: "BitSharesv0XSHA512",
		hashes: []string{
			"caec04bdf7c17f763a9ec7439f7c9abda112f1bfc9b1bb684fef9b6142636979b9896cfc236896d821a69a961a143dd19c96d59777258201f1bbe5ecc2a2ecf5",
		},
		want: "BitShares v0.x - sha512(sha512_bin(pass))",
	},
	{
		name: "BitcoinLitecoinWalletDat",
		hashes: []string{
			"$bitcoin$96$d011a1b6a8d675b7a36d0cd2efaca32a9f8dc1d57d6d01a58399ea04e703e8bbb44899039326f7a00f171a7bbc854a54$16$1563277210780230$158555$96$628835426818227243334570448571536352510740823233055715845322741625407685873076027233865346542174$66$625882875480513751851333441623702852811440775888122046360561760525",
		},
		want: "Bitcoin/Litecoin wallet.dat",
	},
	{
		name: "Bitwarden",
		hashes: []string{
			"$bitwarden$2*100000*2*bm9yZXBseUBoYXNoY2F0Lm5ldA==*+v5rHxYydSRUDlan+4pSoiYQwAgEhdmivlb+exQX+fg=",
		},
		want: "Bitwarden",
	},
	{
		name: "BlockchainMyWallet",
		hashes: []string{
			"$blockchain$288$5420055827231730710301348670802335e45a6f5f631113cb1148a6e96ce645ac69881625a115fd35256636d0908217182f89bdd53256a764e3552d3bfe68624f4f89bb6de60687ff1ebb3cbf4e253ee3bea0fe9d12d6e8325ddc48cc924666dc017024101b7dfb96f1f45cfcf642c45c83228fe656b2f88897ced2984860bf322c6a89616f6ea5800aadc4b293ddd46940b3171a40e0cca86f66f0d4a487aa3a1beb82569740d3bc90bc1cb6b4a11bc6f0e058432cc193cb6f41e60959d03a84e90f38e54ba106fb7e2bfe58ce39e0397231f7c53a4ed4fd8d2e886de75d2475cc8fdc30bf07843ed6e3513e218e0bb75c04649f053a115267098251fd0079272ec023162505725cc681d8be12507c2d3e1c9520674c68428df1739944b8ac",
		},
		want: "Blockchain, My Wallet",
	},
	{
		name: "BlockchainMyWalletV2",
		hashes: []string{
			"$blockchain$v2$5000$288$06063152445005516247820607861028813ccf6dcc5793dc0c7a82dcd604c5c3e8d91bea9531e628c2027c56328380c87356f86ae88968f179c366da9f0f11b09492cea4f4d591493a06b2ba9647faee437c2f2c0caaec9ec795026af51bfa68fc713eaac522431da8045cc6199695556fc2918ceaaabbe096f48876f81ddbbc20bec9209c6c7bc06f24097a0e9a656047ea0f90a2a2f28adfb349a9cd13852a452741e2a607dae0733851a19a670513bcf8f2070f30b115f8bcb56be2625e15139f2a357cf49d72b1c81c18b24c7485ad8af1e1a8db0dc04d906935d7475e1d3757aba32428fdc135fee63f40b16a5ea701766026066fb9fb17166a53aa2b1b5c10b65bfe685dce6962442ece2b526890bcecdeadffbac95c3e3ad32ba57c9e",
		},
		want: "Blockchain, My Wallet V2",
	},
	{
		name: "CRAMMD5",
		hashes: []string{
			"$cram_md5$PG5vLXJlcGx5QGhhc2hjYXQubmV0Pg==$dXNlciA0NGVhZmQyMmZlNzY2NzBmNmIyODc5MDgxYTdmNWY3MQ==",
		},
		want: "CRAM-MD5",
	},
	{
		name: "CRAMMD5Dovecot",
		hashes: []string{
			"{CRAM-MD5}5389b33b9725e5657cb631dc50017ff1535ce4e2a1c414009126506fc4327d0d",
		},
		want: "CRAM-MD5 Dovecot",
	},
	{
		name: "CRC16",
		hashes: []string{
			"c301",
		},
		want: "CRC16",
	},
	{
		name: "CRC16CCITT",
		hashes: []string{
			"d309",
		},
		want: "CRC16-CCITT",
	},
	{
		name: "CRC24",
		hashes: []string{
			"1108c0",
		},
		want: "CRC24",
	},
	{
		name: "CRC32",
		hashes: []string{
			"3099922c",
			"c762de4a:00000000",
		},
		want: "CRC32",
	},
	{
		name: "CRC32B",
		hashes: []string{
			"3099922c",
		},
		want: "CRC32B",
	},
	{
		name: "CRC32C",
		hashes: []string{
			"3099922c",
			"c762de4a:00000000",
		},
		want: "CRC32C",
	},
	{
		name: "CRC64",
		hashes: []string{
			"07022f35f1bd9d09",
		},
		want: "CRC64",
	},
	{
		name: "CRC64Jones",
		hashes: []string{
			"65c1f848fe38cce6:4260950400318054",
		},
		want: "CRC64Jones",
	},
	{
		name: "ChaCha20",
		hashes: []string{
			"$chacha20$*0400000000000003*16*0200000000000001*5152535455565758*6b05fe554b0bc3b3",
		},
		want: "ChaCha20",
	},
	{
		name: "CiscoVPNClientPCFFile",
		hashes: []string{
			"071B15CA6E98F1D339D9B25BE350DAAB9A1C5E0B6499850B610E631FCBFB79A91E4E8FDFF813E064DCECFE6A5233998DC58C9DB8099435DE",
		},
		want: "Cisco VPN Client (PCF-File)",
	},
	{
		name: "CiscoASAMD5",
		hashes: []string{
			"02dMBMYkTdC5Ziyp:36",
		},
		want: "Cisco-ASA MD5",
	},
	{
		name: "CiscoIOS$8$PBKDF2SHA256",
		hashes: []string{
			"$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk",
		},
		want: "Cisco-IOS $8$ (PBKDF2-SHA256)",
	},
	{
		name: "CiscoIOS$9$scrypt",
		hashes: []string{
			"$9$2MJBozw/9R3UsU$2lFhcKvpghcyw8deP25GOfyZaagyUOGBymkryvOdfo6",
		},
		want: "Cisco-IOS $9$ (scrypt)",
	},
	{
		name: "CiscoIOStype4SHA256",
		hashes: []string{
			"2btjjy78REtmYkkW0csHUbJZOstRXoWdX1mGrmmfeHI",
		},
		want: "Cisco-IOS type 4 (SHA256)",
	},
	{
		name: "CiscoPIXMD5",
		hashes: []string{
			"dRRVnUmUHXOTt9nk",
		},
		want: "Cisco-PIX MD5",
	},
	{
		name: "CitrixNetScalerSHA1",
		hashes: []string{
			"1765058016a22f1b4e076dccd1c3df4e8e5c0839ccded98ea",
		},
		want: "Citrix NetScaler (SHA1)",
	},
	{
		name: "CitrixNetScalerSHA512",
		hashes: []string{
			"2f9282ade42ce148175dc3b4d8b5916dae5211eee49886c3f7cc768f6b9f2eb982a5ac2f2672a0223999bfd15349093278adf12f6276e8b61dacf5572b3f93d0b4fa886ce",
		},
		want: "Citrix NetScaler (SHA512)",
	},
	{
		name: "ClavisterSecureGateway",
		hashes: []string{
			"crypt1:fnd+8xl+U1E=:Wc30H8MPgAc=",
		},
		want: "Clavister Secure Gateway",
	},
	{
		name: "ColdFusion10",
		hashes: []string{
			"aee9edab5653f509c4c63e559a5e967b4c112273bc6bd84525e630a3f9028dcb:5136256866783777334574783782810410706883233321141647265340462733",
		},
		want: "ColdFusion 10+",
	},
	{
		name: "Crypt16",
		hashes: []string{
			"aaX/UmCcBrceQ0kQGGWKTbuE",
		},
		want: "Crypt16",
	},
	{
		name: "DESPT$SaltKey$Pass)",
		hashes: []string{
			"a28bc61d44bb815c:1172075784504605",
		},
		want: "DES (PT = $salt, key = $pass)",
	},
	{
		name: "DNSSECNSEC3",
		hashes: []string{
			"7b5n74kq8r441blc2c5qbbat19baj79r:.lvdsiqfj.net:33164473:1",
		},
		want: "DNSSEC (NSEC3)",
	},
	{
		name: "DPAPIMasterkeyFilev1LocalContext",
		hashes: []string{
			"$DPAPImk$1*1*S-15-21-466364039-425773974-453930460-1925*des3*sha1*24000*b038489dee5ad04e3e3cab4d957258b5*208*cb9b5b7d96a0d2a00305ca403d3fd9c47c561e35b4b2cf3aebfd1d3199a6481d56972be7ebd6c291b199e6f1c2ffaee91978706737e9b1209e6c7d3aa3d8c3c3e38ad1ccfa39400d62c2415961c17fd0bd6b0f7bbd49cc1de1a394e64b7237f56244238da8d37d78",
		},
		want: "DPAPI masterkey file v1 + local context",
	},
	{
		name: "DPAPIMasterkeyFilev1Context3",
		hashes: []string{
			"$DPAPImk$1*3*S-15-21-407415836-404165111-436049749-1915*des3*sha1*14825*3e86e7d8437c4d5582ff668a83632cb2*208*96ad763b59e67c9f5c3d925e42bbe28a1412b919d1dc4abf03b2bed4c5c244056c14931d94d441117529b7171dfd6ebbe6eecf5d958b65574c293778fbadb892351cc59d5c65d65d2fcda73f5b056548a4a5550106d03d0c39d3cca7e5cdc0d521f48ac9e51cecc5",
		},
		want: "DPAPI masterkey file v1 (context 3)",
	},
	{
		name: "DPAPIMasterkeyFilev2ActiveDirectoryDomainContext",
		hashes: []string{
			"$DPAPImk$2*2*S-15-21-423929668-478423897-489523715-1834*aes256*sha512*8000*740866e4105c77f800f02d367dd96699*288*ebc2907e16245dfe6c902ad4be70a079e62204c8a947498455056d150e6babb3c90b1616a8dff0e390dd26dda1978dffcbd7b9d7d1ea5c6d3e4df36db4d977051ec01fd6f0882a597c51834cb86445cad50c716f48b37cfd24339d8b43da771526fb01376798251edaa868fa2b1fa85c4142864b899987d4bbdc87b53433ed945fa4ab49c7f9d4d01df3ae19f25013b2",
		},
		want: "DPAPI masterkey file v2 + Active Directory domain context",
	},
	{
		name: "DahuaAuthenticationMD5",
		hashes: []string{
			"GRuHbyVp",
		},
		want: "Dahua Authentication MD5",
	},
	{
		name: "DjangoDESCryptWrapper",
		hashes: []string{
			"crypt$cd1a4$cdlRbNJGImptk",
		},
		want: "Django (DES Crypt Wrapper)",
	},
	{
		name: "DjangoMD5",
		hashes: []string{
			"md5$be7b1$4e9c5b51bd070727b0ed21956cb68de7",
		},
		want: "Django (MD5)",
	},
	{
		name: "DjangoPBKDF2HMACSHA1",
		hashes: []string{
			"pbkdf2_sha1$60000$VK7NMb1gBMQJ$5frCW3jgMceSkjJgNdAq4LxOg0s=",
		},
		want: "Django (PBKDF2-HMAC-SHA1)",
	},
	{
		name: "DjangoPBKDF2SHA256",
		hashes: []string{
			"pbkdf2_sha256$20000$H0dPx8NeajVu$GiC4k5kqbbR9qWBlsRgDywNqC2vd9kqfk7zdorEnNas=",
		},
		want: "Django (PBKDF2-SHA256)",
	},
	{
		name: "DjangoSHA1",
		hashes: []string{
			"sha1$fe76b$02d5916550edf7fc8c886f044887f4b1abf9b013",
		},
		want: "Django (SHA-1)",
	},
	{
		name: "DjangoSHA256",
		hashes: []string{
			"sha256$12345678$9171fc5e7cd440fac61adc27cbebb78ff028a19a1abeaa041807a5ea936fbd94",
		},
		want: "Django (SHA-256)",
	},
	{
		name: "DjangoSHA384",
		hashes: []string{
			"sha384$12345678$fe014d8b5dc1733a9727330fb8b4695f82c7e833382a27c513b258f46f29ababb9d9963ddaa13db306b2bbd1459b95e6",
		},
		want: "Django (SHA-384)",
	},
	{
		name: "Djangobcrypt",
		hashes: []string{
			"bcrypt$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6",
		},
		want: "Django (bcrypt)",
	},
	{
		name: "DjangobcryptSHA256",
		hashes: []string{
			"bcrypt_sha256$$2a$12$KQV0bIQYx798IUJmJFjm7.IKJoxrZSiAVKDLWCcLFBFF.gdcCVuz6",
		},
		want: "Django (bcrypt-SHA256)",
	},
	{
		name: "DomainCachedCredentialsDCCMSCache",
		hashes: []string{
			"4dd8965d1d476fa0d026722989a6b772:3060147285011",
		},
		want: "Domain Cached Credentials (DCC), MS Cache",
	},
	{
		name: "DomainCachedCredentials2DCC2MSCache2",
		hashes: []string{
			"$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f",
		},
		want: "Domain Cached Credentials 2 (DCC2), MS Cache 2",
	},
	{
		name: "Drupal7",
		hashes: []string{
			"$S$C33783772bRXEx1aCsvY.dqgaaSu76XmVlKrW9Qu8IQlvxHlmzLf",
		},
		want: "Drupal7",
	},
	{
		name: "ELF32",
		hashes: []string{
			"00067894",
		},
		want: "ELF-32",
	},
	{
		name: "EPi",
		hashes: []string{
			"0x326C6D7B4E4F794B79474E36704F35723958397163735263516265456E31 0xAFC55E260B8F45C0C6512BCE776C1AD8312B56E6",
		},
		want: "EPi",
	},
	{
		name: "EggdropIRCBot",
		hashes: []string{
			"+3nynz1ThEqm.",
		},
		want: "Eggdrop IRC Bot",
	},
	{
		name: "ElectrumWalletSaltType1To3",
		hashes: []string{
			"$electrum$1*44358283104603165383613672586868*c43a6632d9f59364f74c395a03d8c2ea",
		},
		want: "Electrum Wallet (Salt-Type 1-3)",
	},
	{
		name: "ElectrumWalletSaltType4",
		hashes: []string{
			"$electrum$4*03eae309d8bda5dcbddaae8145469193152763894b7260a6c4ba181b3ac2ed5653*8c594086a64dc87a9c1f8a69f646e31e8d3182c3c722def4427aa20684776ac26092c6f60bf2762e27adfa93fe1e952dcb8d6362224b9a371953aa3a2edb596ce5eb4c0879c4353f2cc515ec6c9e7a6defa26c5df346d18a62e9d40fcc606bc8c34322bf2212f77770a683788db0baf4cb43595c2a27fe5ff8bdcb1fd915bcd725149d8ee8f14c71635fecb04da5dde97584f4581ceb7d907dceed80ae5daa8352dda20b25fd6001e99a96b7cf839a36cd3f5656304e6998c18e03dd2fb720cb41386c52910c9cb83272c3d50f3a6ff362ab8389b0c21c75133c971df0a75b331796371b060b32fe1673f4a041d7ae08bbdeffb45d706eaf65f99573c07972701c97766b4d7a8a03bba0f885eb3845dfd9152286e1de1f93e25ce04c54712509166dda80a84c2d34652f68e6c01e662f8b1cc7c15103a4502c29332a4fdbdda470c875809e15aab3f2fcb061ee96992ad7e8ab9da88203e35f47d6e88b07a13b0e70ef76de3be20dc06facbddc1e47206b16b44573f57396265116b4d243e77d1c98bc2b28aa3ec0f8d959764a54ecdd03d8360ff2823577fe2183e618aac15b30c1d20986841e3d83c0bfabcedb7c27ddc436eb7113db927e0beae7522b04566631a090b214660152a4f4a90e19356e66ee7309a0671b2e7bfde82667538d193fc7e397442052c6c611b6bf0a04f629a1dc7fa9eb44bfad1bfc6a0bce9f0564c3b483737e447720b7fd038c9a961a25e9594b76bf8c8071c83fcacd689c7469f698ee4aee4d4f626a73e21ce4967e705e4d83e1145b4260330367d8341c84723a1b02567ffbab26aac3afd1079887b4391f05d09780fc65f8b4f68cd51391c06593919d7eafd0775f83045b8f5c2e59cef902ff500654ea29b7623c7594ab2cc0e05ffe3f10abc46c9c5dac824673c307dcbff5bc5f3774141ff99f6a34ec4dd8a58d154a1c72636a2422b8fafdef399dec350d2b91947448582d52291f2261d264d29399ae3c92dc61769a49224af9e7c98d74190f93eb49a44db7587c1a2afb5e1a4bec5cdeb8ad2aac9728d5ae95600c52e9f063c11cdb32b7c1d8435ce76fcf1fa562bd38f14bf6c303c70fb373d951b8a691ab793f12c0f3336d6191378bccaed32923bba81868148f029e3d5712a2fb9f610997549710716db37f7400690c8dfbed12ff0a683d8e4d0079b380e2fd856eeafb8c6eedfac8fb54dacd6bd8a96e9f8d23ea87252c1a7c2b53efc6e6aa1f0cc30fbaaf68ee7d46666afc15856669cd9baebf9397ff9f322cce5285e68a985f3b6aadce5e8f14e9f9dd16764bc4e9f62168aa265d8634ab706ed40b0809023f141c36717bd6ccef9ec6aa6bfd2d00bda9375c2fee9ebba49590a166*1b0997cf64bb2c2ff88cb87bcacd9729d404bd46db18117c20d94e67c946fedc",
		},
		want: "Electrum Wallet (Salt-Type 4)",
	},
	{
		name: "ElectrumWalletSaltType5",
		hashes: []string{
			"$electrum$5*02170fee7c35f1ef3b229edc90fbd0793b688a0d6f41137a97aab2343d315cce16*94cf72d8f5d774932b414a3344984859e43721268d2eb35fa531de5a2fc7024b463c730a54f4f46229dd9fede5034b19ac415c2916e9c16b02094f845795df0c397ff76d597886b1f9e014ad1a8f64a3f617d9900aa645b3ba86f16ce542251fc22c41d93fa6bc118be96d9582917e19d2a299743331804cfc7ce2c035367b4cbcfb70adfb1e10a0f2795769f2165d8fd13daa8b45eeac495b5b63e91a87f63b42e483f84a881e49adecacf6519cb564694b42dd9fe80fcbc6cdb63cf5ae33f35255266f5c2524dd93d3cc15eba0f2ccdc3c109cc2d7e8f711b8b440f168caf8b005e8bcdfe694148e94a04d2a738f09349a96600bd8e8edae793b26ebae231022f24e96cb158db141ac40400a9e9ef099e673cfe017281537c57f82fb45c62bdb64462235a6eefb594961d5eb2c46537958e4d04250804c6e9f343ab7a0db07af6b8a9d1a6c5cfcd311b8fb8383ac9ed9d98d427d526c2f517fc97473bd87cb59899bd0e8fb8c57fa0f7e0d53daa57c972cf92764af4b1725a5fb8f504b663ec519731929b3caaa793d8ee74293eee27d0e208a60e26290bc546e6fa9ed865076e13febfea249729218c1b5752e912055fbf993fbac5df2cca2b37c5e0f9c30789858ceeb3c482a8db123966775aeed2eee2fc34efb160d164929f51589bff748ca773f38978bff3508d5a7591fb2d2795df983504a788071f469d78c88fd7899cabbc5804f458653d0206b82771a59522e1fa794d7de1536c51a437f5d6df5efd6654678e5794ca429b5752e1103340ed80786f1e9da7f5b39af628b2212e4d88cd36b8a7136d50a6b6e275ab406ba7c57cc70d77d01c4c16e9363901164fa92dc9e9b99219d5376f24862e775968605001e71b000e2c7123b4b43f3ca40db17efd729388782e46e64d43ccb947db4eb1473ff1a3836b74fe312cd1a33b73b8b8d80c087088932277773c329f2f66a01d6b3fc1e651c56959ebbed7b14a21b977f3acdedf1a0d98d519a74b50c39b3052d840106da4145345d86ec0461cddafacc2a4f0dd646457ad05bf04dcbcc80516a5c5ed14d2d639a70e77b686f19cbfb63f546d81ae19cc8ba35cce3f3b5b9602df25b678e14411fecec87b8347f5047513df415c6b1a3d39871a6bcb0f67d9cf8311596deae45fd1d84a04fd58f1fd55c5156b7309af09094c99a53674809cb87a45f95a2d69f9997a38085519cb4e056f9efd56672a2c1fe927d5ea8eec25b8aff6e56f9a2310f1a481daf407b8adf16201da267c59973920fd21bb087b88123ef98709839d6a3ee34efb8ccd5c15ed0e46cff3172682769531164b66c8689c35a26299dd26d09233d1f64f9667474141cf9c6a6de7f2bc52c3bb44cfe679ff4b912c06df406283836b3581773cb76d375304f46239da5996594a8d03b14c02f1b35a432dc44a96331242ae31174*33a7ee59d6d17ed1ee99dc0a71771227e6f3734b17ba36eb589bdced56244135",
		},
		want: "Electrum Wallet (Salt-Type 5)",
	},
	{
		name: "Episerver6x<NET4",
		hashes: []string{
			"$episerver$*0*bEtiVGhPNlZpcUN4a3ExTg==*utkfN0EOgljbv5FoZ6+AcZD5iLk",
		},
		want: "Episerver 6.x < .NET 4",
	},
	{
		name: "Episerver6x>=NET4",
		hashes: []string{
			"$episerver$*1*MDEyMzQ1Njc4OWFiY2RlZg==*lRjiU46qHA7S6ZE7RfKUcYhB85ofArj1j7TrCtu3u6Y",
		},
		want: "Episerver 6.x >= .NET 4",
	},
	{
		name: "EthereumPreSaleWalletPBKDF2HMACSHA256",
		hashes: []string{
			"$ethereum$w*e94a8e49deac2d62206bf9bfb7d2aaea7eb06c1a378cfc1ac056cc599a569793c0ecc40e6a0c242dee2812f06b644d70f43331b1fa2ce4bd6cbb9f62dd25b443235bdb4c1ffb222084c9ded8c719624b338f17e0fd827b34d79801298ac75f74ed97ae16f72fccecf862d09a03498b1b8bd1d984fc43dd507ede5d4b6223a582352386407266b66c671077eefc1e07b5f42508bf926ab5616658c984968d8eec25c9d5197a4a30eed54c161595c3b4d558b17ab8a75ccca72b3d949919d197158ea5cfbc43ac7dd73cf77807dc2c8fe4ef1e942ccd11ec24fe8a410d48ef4b8a35c93ecf1a21c51a51a08f3225fbdcc338b1e7fdafd7d94b82a81d88c2e9a429acc3f8a5974eafb7af8c912597eb6fdcd80578bd12efddd99de47b44e7c8f6c38f2af3116b08796172eda89422e9ea9b99c7f98a7e331aeb4bb1b06f611e95082b629332c31dbcfd878aed77d300c9ed5c74af9cd6f5a8c4a261dd124317fb790a04481d93aec160af4ad8ec84c04d943a869f65f07f5ccf8295dc1c876f30408eac77f62192cbb25842470b4a5bdb4c8096f56da7e9ed05c21f61b94c54ef1c2e9e417cce627521a40a99e357dd9b7a7149041d589cbacbe0302db57ddc983b9a6d79ce3f2e9ae8ad45fa40b934ed6b36379b780549ae7553dbb1cab238138c05743d0103335325bd90e27d8ae1ea219eb8905503c5ad54fa12d22e9a7d296eee07c8a7b5041b8d56b8af290274d01eb0e4ad174eb26b23b5e9fb46ff7f88398e6266052292acb36554ccb9c2c03139fe72d3f5d30bd5d10bd79d7cb48d2ab24187d8efc3750d5a24980fb12122591455d14e75421a2074599f1cc9fdfc8f498c92ad8b904d3c4307f80c46921d8128*f3abede76ac15228f1b161dd9660bb9094e81b1b*d201ccd492c284484c7824c4d37b1593",
		},
		want: "Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256",
	},
	{
		name: "EthereumWalletPBKDF2HMACSHA256",
		hashes: []string{
			"$ethereum$p*262144*3238383137313130353438343737383736323437353437383831373034343735*06eae7ee0a4b9e8abc02c9990e3730827396e8531558ed15bb733faf12a44ce1*e6d5891d4f199d31ec434fe25d9ecc2530716bc3b36d5bdbc1fab7685dda3946",
		},
		want: "Ethereum Wallet, PBKDF2-HMAC-SHA256",
	},
	{
		name: "EthereumWalletSCRYPT",
		hashes: []string{
			"$ethereum$s*262144*1*8*3436383737333838313035343736303637353530323430373235343034363130*8b58d9d15f579faba1cd13dd372faeb51718e7f70735de96f0bcb2ef4fb90278*8de566b919e6825a65746e266226316c1add8d8c3d15f54640902437bcffc8c3",
		},
		want: "Ethereum Wallet, SCRYPT",
	},
	{
		name: "FCS16",
		hashes: []string{
			"a36b",
		},
		want: "FCS-16",
	},
	{
		name: "FCS32",
		hashes: []string{
			"11cd82ed",
		},
		want: "FCS-32",
	},
	{
		name: "FNV132",
		hashes: []string{
			"4ab55bf6",
		},
		want: "FNV-132",
	},
	{
		name: "FNV164",
		hashes: []string{
			"8d0b972bd2e4ce16",
		},
		want: "FNV-164",
	},
	{
		name: "FairlySecureHashedPassword",
		hashes: []string{
			"{FSHP1|16|16384}PtoqcGUetmVEy/uR8715TNqKa8+teMF9qZO1lA9lJNUm1EQBLPZ+qPRLeEPHqy6C",
		},
		want: "Fairly Secure Hashed Password",
	},
	{
		name: "FileVault2",
		hashes: []string{
			"$fvde$1$16$84286044060108438487434858307513$20000$f1620ab93192112f0a23eea89b5d4df065661f974b704191",
		},
		want: "FileVault 2",
	},
	{
		name: "FileZillaServer>=0955",
		hashes: []string{
			"632c4952b8d9adb2c0076c13b57f0c934c80bdc14fc1b4c341c2e0a8fd97c4528729c7bd7ed1268016fc44c3c222445ebb880eca9a6638ea5df74696883a2978:0608516311148050266404072407085605002866301131581532805665756363",
		},
		want: "FileZilla Server >= 0.9.55",
	},
	{
		name: "Fletcher32",
		hashes: []string{
			"8a01d403",
		},
		want: "Fletcher-32",
	},
	{
		name: "FortiGateFortiOS",
		hashes: []string{
			"AK1AAECAwQFBgcICRARNGqgeC3is8gv2xWWRony9NJnDgE=",
		},
		want: "FortiGate (FortiOS)",
	},
	{
		name: "FortiGate256FortiOS256",
		hashes: []string{
			"SH2MCKr6kt9rLQKbn/YTlncOnR6OtcJ1YL/h8hw2wWicjSRf3bbkSrL+q6cDpg=",
		},
		want: "FortiGate256 (FortiOS256)",
	},
	{
		name: "GHash323",
		hashes: []string{
			"0001371a",
		},
		want: "GHash-32-3",
	},
	{
		name: "GHash325",
		hashes: []string{
			"0036deca",
		},
		want: "GHash-32-5",
	},
	{
		name: "GOSTR34112012Streebog256-bitbigendian",
		hashes: []string{
			"57e9e50caec93d72e9498c211d6dc4f4d328248b48ecf46ba7abfa874f666e36",
		},
		want: "GOST R 34.11-2012 (Streebog) 256-bit, big-endian",
	},
	{
		name: "GOSTR34112012Streebog512bitbigendian",
		hashes: []string{
			"5d5bdba48c8f89ee6c0a0e11023540424283e84902de08013aeeb626e819950bb32842903593a1d2e8f71897ff7fe72e17ac9ba8ce1d1d2f7e9c4359ea63bdc3",
		},
		want: "GOST R 34.11-2012 (Streebog) 512-bit, big-endian",
	},
	{
		name: "GOSTR341194",
		hashes: []string{
			"df226c2c6dcb1d995c0299a33a084b201544293c31fc3d279530121d36bbcea9",
		},
		want: "GOST R 34.11-94",
	},
	{
		name: "GPGAES128AES256SHA1$Pass",
		hashes: []string{
			"$gpg$*1*348*1024*8833fa3812b5500aa9eb7e46febfa31a0584b7e4a5b13c198f5c9b0814243895cce45ac3714e79692fb5a130a1c943b9130315ce303cb7e6831be68ce427892858f313fc29f533434dbe0ef26573f2071bbcc1499dc49bda90648221ef3823757e2fba6099a18c0c83386b21d8c9b522ec935ecd540210dbf0f21c859429fd4d35fa056415d8087f27b3e66b16081ea18c544d8b2ea414484f17097bc83b773d92743f76eb2ccb4df8ba5f5ff84a5474a5e8a8e5179a5b0908503c55e428de04b40628325739874e1b4aa004c4cbdf09b0b620990a8479f1c9b4187e33e63fe48a565bc1264bbf4062559631bef9e346a7217f1cabe101a38ac4be9fa94f6dafe6b0301e67792ed51bca04140cddd5cb6e80ac6e95e9a09378c9651588fe360954b622c258a3897f11246c944a588822cc6daf1cb81ccc95098c3bea8432f1ee0c663b193a7c7f1cdfeb91eee0195296bf4783025655cbebd7c70236*3*254*2*7*16*a47ef38987beab0a0b9bfe74b72822e8*65536*1f5c90d9820997db",
		},
		want: "GPG (AES-128/AES-256 (SHA-1($pass)))",
	},
	{
		name: "GPGAES128AES256SHA512$Pass",
		hashes: []string{
			"$gpg$*1*668*2048*57e1f19c69a86038e23d7e5af5d810f4f86d32e9aaaf04b54281cda2194dcca99ee1f23f4aa3a011d5d2dc9e47689c449f398d315f91a03f4765742d20a7046e986a9696f0e07380a73fdd61e7ab2caa463a049a5869e008e16bb30d22f93f9aa8b0fdd41d2b19e669d58ca462498905e79944bff578c24139a88ef44582aef93f94fe22406a3ae32dcc0f0602e2f4345db2bd9d775eaeb14a8d7aff963e1ca8c29bab2fc3d459941587f4242af6e100e2e668a6c9247c19969ba294f6f2ab60ef84d42aab2e3512153a283d321442840189733dc6024dab0ea5d10d2e07fee914fc2e7177b310e8835bf8a5ffe1bde5ce0a74d3dd570c1b2652672873d3c520364acc0af35f5f7d0e0e95df8c2db3855936e0a4a24cc463bf277b0c5ea37d4ac1ddae6ef9da18852620de15ab648306f3d7acbb918e79f3ab7a3eaf4f59416560c4d31d8a0220c3301c95db4b8fe6b69348657aed52d5e15aefb17fedd15a50630a4edbad362ba9b79a048b4966a70643d8fa31fb397a531db85e8ad5bb169f5188449dbcc1bbaf42440d1794a34296c2407092c76e59544133959309ce42a05899162c55a865018085a4c57068294a5389cf6fbf1c93b5ab7732625fb6a465bd7ec51a128c2f9b0cf3fd0367f92667098b3a8af40f9f434a2a727b09bddbad1762127cc785eda419ac3ff24c8724e04ea2d330b0b441f34623955efd383f20578cdc527f3076ee068b727cd399ce17ff9d5233409b2d16d55c5c80cb8ca01019cd068c6e803217d6f2b7124e354b89de0eb0dfd241384026a1cdca529b6fed37aa0ececb0d6c26de06407d75a6e3108b0d25621db418206291a67216306e1a18c992736e45ef7f87373c0a3f28ddc1b4543604cd154f6b79265a6d8c13550078c3bcf55063263e5bc5cae6b925c1dbb67f972e234006867849e653*3*254*10*9*16*d1547688c9cc944482d16dff17df0858*20971520*1fef4e57e302d34e",
		},
		want: "GPG (AES-128/AES-256 (SHA-512($pass)))",
	},
	{
		name: "GPGAES128AES256SHA256$Pass",
		hashes: []string{
			"$gpg$*1*668*2048*e75985b4e7d0bce9e38925a5cf69494ae9a2ccfe2973f077d9423642fffec8bee0e327178a4a3431875ca1f377b9f89269e7c42b94150859d9e5bf5c4504d63076b270118183dda75d253492be8b680c0061e7f130010a00a09a0456710051f2483052ad209fcb9f194f78ecd04fd04953fa1cd6f7ce9babca8b2ee6432730de069648460b2822fe355ed19e0055c69251097681901d7183626019d938727399df47f5249f25b1c73e8654bf935014533845f278e6dd94b8c2964ad6a87c718967686f39a88b21a0e5a93321d4733c81d9310955db6990d8cd02bcf73159b1f48f5615def601aa3e12bf30384da41b558b1eef1111cfc85c8772c123a7b977e2ba399f65679c35b9a2abfde0230a5706fe99f5460c700b1498b1661353ec30eab25defb9af2e7e744fd050d2e7c87542d8bc49e728a7734accf2801dc5972192670858f2004308f3afdd94acd44e1161c44dd372296ca7fe40cbb541c21d640a10df34460c4f5c7cd1bf3b3282668d7edb53be4d843aef4b6f0357526d9c4432aa2a45e113a73e75bfec98cb4cc020ab6cca35336fd188140fd16183dbe288707421e698b6e4801508ae903de3e5d600bd613ea612af92780e53be37722897edb8a588193e7d28819c2f0cbb4e97c3e830113ce14ab05ddb82552fc5e82c386ec2fe9b2d86fc7ade39e341e3dd828502cc3dd038cb21cb0512e79dca9f5a9eae78b2e91aa0732ac77fbc3bc5575c210f519c178669ea99bef62eb6761dfa76407d0d501b07a696a0214dafde7b0bfb48e8ba445b6b42a859a63cb91c9d991ed030ef9e6c63f53b395e14821d7039e4455e0e3712f77f64b7abaa04467bd5b9be26c5e098430187676d0aa7206e2e4fa2e5b7bd486d18b0f3859e94319ccac587574a7bae6ccb3e9414cc769761cf6a0fa1b33cccd1a4b0b04c0d52cd*3*254*8*9*16*343d26cf2c10a8f8a161874fbb218c12*65536*666ae8d1c98404b0",
		},
		want: "GPG (AES-128/AES-256 (SHA-256($pass)))",
	},
	{
		name: "GRUB2",
		hashes: []string{
			"grub.pbkdf2.sha512.10000.7d391ef48645f626b427b1fae06a7219b5b54f4f02b2621f86b5e36e83ae492bd1db60871e45bc07925cecb46ff8ba3db31c723c0c6acbd4f06f60c5b246ecbf.26d59c52b50df90d043f070bd9cbcd92a74424da42b3666fdeb08f1a54b8f1d2f4f56cf436f9382419c26798dc2c209a86003982b1e5a9fcef905f4dfaa4c524",
		},
		want: "GRUB 2",
	},
	{
		name: "HAS160",
		hashes: []string{
			"6746df56b6210ed660ab01b8d8886a8237389bd5",
		},
		want: "HAS-160",
	},
	{
		name: "HMACMD5Key$Pass",
		hashes: []string{
			"fc741db0a2968c39d9c2a5cc75b05370:1234",
		},
		want: "HMAC-MD5 (key = $pass)",
	},
	{
		name: "HMACMD5Key$Salt",
		hashes: []string{
			"bfd280436f45fa38eaacac3b00518f29:1234",
		},
		want: "HMAC-MD5 (key = $salt)",
	},
	{
		name: "HMACSHA1Key$Pass",
		hashes: []string{
			"c898896f3f70f61bc3fb19bef222aa860e5ea717:1234",
		},
		want: "HMAC-SHA1 (key = $pass)",
	},
	{
		name: "HMACSHA1Key$Salt",
		hashes: []string{
			"d89c92b4400b15c39e462a8caa939ab40c3aeeea:1234",
		},
		want: "HMAC-SHA1 (key = $salt)",
	},
	{
		name: "HMACSHA256Key$Pass",
		hashes: []string{
			"abaf88d66bf2334a4a8b207cc61a96fb46c3e38e882e6f6f886742f688b8588c:1234",
		},
		want: "HMAC-SHA256 (key = $pass)",
	},
	{
		name: "HMACSHA256Key$Salt",
		hashes: []string{
			"8efbef4cec28f228fa948daaf4893ac3638fbae81358ff9020be1d7a9a509fc6:1234",
		},
		want: "HMAC-SHA256 (key = $salt)",
	},
	{
		name: "HMACSHA512Key$Pass",
		hashes: []string{
			"94cb9e31137913665dbea7b058e10be5f050cc356062a2c9679ed0ad6119648e7be620e9d4e1199220cd02b9efb2b1c78234fa1000c728f82bf9f14ed82c1976:1234",
		},
		want: "HMAC-SHA512 (key = $pass)",
	},
	{
		name: "HMACSHA512Key$Salt",
		hashes: []string{
			"7cce966f5503e292a51381f238d071971ad5442488f340f98e379b3aeae2f33778e3e732fcc2f7bdc04f3d460eebf6f8cb77da32df25500c09160dd3bf7d2a6b:1234",
		},
		want: "HMAC-SHA512 (key = $salt)",
	},
	{
		name: "HMACStreebog256Key$PassBigEndian",
		hashes: []string{
			"0f71c7c82700c9094ca95eee3d804cc283b538bec49428a9ef8da7b34effb3ba:08151337",
		},
		want: "HMAC-Streebog-256 (key = $pass), big-endian",
	},
	{
		name: "HMACStreebog256Key$SaltBigEndian",
		hashes: []string{
			"d5c6b874338a492ac57ddc6871afc3c70dcfd264185a69d84cf839a07ef92b2c:08151337",
		},
		want: "HMAC-Streebog-256 (key = $salt), big-endian",
	},
	{
		name: "HMACStreebog512Key$PassBigEndian",
		hashes: []string{
			"be4555415af4a05078dcf260bb3c0a35948135df3dbf93f7c8b80574ceb0d71ea4312127f839b7707bf39ccc932d9e7cb799671183455889e8dde3738dfab5b6:08151337",
		},
		want: "HMAC-Streebog-512 (key = $pass), big-endian",
	},
	{
		name: "HMACStreebog512Key$SaltBigEndian",
		hashes: []string{
			"bebf6831b3f9f958acb345a88cb98f30cb0374cff13e6012818487c8dc8d5857f23bca2caed280195ad558b8ce393503e632e901e8d1eb2ccb349a544ac195fd:08151337",
		},
		want: "HMAC-Streebog-512 (key = $salt), big-endian",
	},
	{
		name: "HalfMD5",
		hashes: []string{
			"8743b52063cd8409",
		},
		want: "Half MD5",
	},
	{
		name: "Haval128",
		hashes: []string{
			"c68f39913f901f3ddf44c707357a7d70",
		},
		want: "Haval-128",
	},
	{
		name: "Haval160",
		hashes: []string{
			"d353c3ae22a25401d257643836d7231a9a95f953",
		},
		want: "Haval-160",
	},
	{
		name: "Haval192",
		hashes: []string{
			"e9c48d7903eaf2a91c5b350151efcb175c0fc82de2289a4e",
		},
		want: "Haval-192",
	},
	{
		name: "Haval224",
		hashes: []string{
			"c5aae9d47bffcaaf84a8c6e7ccacd60a0dd1932be7b1a192b9214b6d",
		},
		want: "Haval-224",
	},
	{
		name: "Haval256",
		hashes: []string{
			"4f6938531f0bc8991f62da7bbd6f7de3fad44562b8c6f4ebf146d5b4e46f7c17",
		},
		want: "Haval-256",
	},
	{
		name: "HuaweiSHA1MD5$Pass$Salt",
		hashes: []string{
			"53c724b7f34f09787ed3f1b316215fc35c789504:hashcat1",
		},
		want: "Huawei sha1(md5($pass).$salt)",
	},
	{
		name: "IKEPSKMD5",
		hashes: []string{
			"e957a6a0f53ce06a56e4d82e96bc925ffa3cf7b79f6500b667edad5a1d7bad4619efa734f75cca9c4222fbb169f71d4240aced349eb7126f35cf94772b4af373ddf9b3f1ab3a9ff8cd2705417dca7e36dd9026bd0d472459cea7ad245ce57e4bf7d36efdea2a782978c6161eae98f01eac1ee05578f8e524a0d7748c5a1ec2de:647c051436ee84b39a514fd5f2da24fd3bdbb245ef3ed05cb362c58916bbb2cb93a93e3ec33da27404b82125cfd354c0114a3d10dfca26fab139f91046f2ad996f6091ac7a729305272696ac1769991b81a30826e24cee586f3f383b5e035820e17d9715db433ac75f204f20153a12cf7ee4fa7d11b2823e424c26cb513eb26b:fb3678377967e4db:708993a01df48348:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:01110000c0a83965:19004c6aa04dba354599f0d6afbc866970d751e4:6074841c25c83a0c1abfa348fee2d133399595f2:19a3428d90eb5045363a58dc33f51941",
		},
		want: "IKE-PSK MD5",
	},
	{
		name: "IKEPSKSHA1",
		hashes: []string{
			"7a1115b74a1b9d63de62627bdd029aa7a50df83ddbaba88c47d3e51833d21984fb463a2604ba0c82611a11edee7406e1826b2c70410d2797487d1220a4f716d7532fcd73e82b2fd6304f9af5dd1bc0a5dc1eb58bee978f95ffc8b6dc4401d4d2720978f4b0e69ae4dd96e61a1f23a347123aa242f893b33ac74fa234366dc56c:7e599b0168b56608f8a512b68bc7ea47726072ca8e66ecb8792a607f926afc2c3584850773d91644a3186da80414c5c336e07d95b891736f1e88eb05662bf17659781036fa03b869cb554d04689b53b401034e5ea061112066a89dcf8cbe3946e497feb8c5476152c2f8bc0bef4c2a05da51344370682ffb17ec664f8bc07855:419011bd5632fe07:169168a1ac421e4d:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:01110000c0a83965:ee4e517ba0f721798209d04dfcaf965758c4857e:48aada032ae2523815f4ec86758144fa98ad533c:e65f040dad4a628df43f3d1253f821110797a106",
		},
		want: "IKE-PSK SHA1",
	},
	{
		name: "IPMI2RAKPHMACSHA1",
		hashes: []string{
			"b7c2d6f13a43dce2e44ad120a9cd8a13d0ca23f0414275c0bbe1070d2d1299b1c04da0f1a0f1e4e2537300263a2200000000000000000000140768617368636174",
		},
		want: "IPMI2 RAKP HMAC-SHA1",
	},
	{
		name: "JKSJavaKeyStorePrivateKeysSHA1",
		hashes: []string{
			"$jksprivk$*5A3AA3C3B7DD7571727E1725FB09953EF3BEDBD9*0867403720562514024857047678064085141322*81*C3*50DDD9F532430367905C9DE31FB1*test",
		},
		want: "JKS Java Key Store Private Keys (SHA1)",
	},
	{
		name: "JWTJSONWebToken",
		hashes: []string{
			"eyJhbGciOiJIUzI1NiJ9.eyIzNDM2MzQyMCI6NTc2ODc1NDd9.f1nXZ3V_Hrr6ee-AFCTLaHRnrkiKmio2t3JqwL32guY",
		},
		want: "JWT (JSON Web Token)",
	},
	{
		name: "JavaObjectHashCode",
		hashes: []string{
			"29937c08",
		},
		want: "Java Object hashCode()",
	},
	{
		name: "Joaat",
		hashes: []string{
			"0e34a138",
		},
		want: "Joaat",
	},
	{
		name: "Joomla<2518",
		hashes: []string{
			"19e0e8d91c722e7091ca7a6a6fb0f4fa:54718031842521651757785603028777",
		},
		want: "Joomla < 2.5.18",
	},
	{
		name: "JuniperIVE",
		hashes: []string{
			"3u+UR6n8AgABAAAAHxxdXKmiOmUoqKnZlf8lTOhlPYy93EAkbPfs5+49YLFd/B1+omSKbW7DoqNM40/EeVnwJ8kYoXv9zy9D5C5m5A==",
		},
		want: "Juniper IVE",
	},
	{
		name: "JuniperNetScreenSSGScreenOS",
		hashes: []string{
			"nNxKL2rOEkbBc9BFLsVGG6OtOUO/8n:user",
		},
		want: "Juniper NetScreen/SSG (ScreenOS)",
	},
	{
		name: "JuniperNetBSDsha1crypt",
		hashes: []string{
			"$sha1$15100$jiJDkz0E$E8C7RQAD3NetbSDz7puNAY.5Y2jr",
		},
		want: "Juniper/NetBSD sha1crypt",
	},
	{
		name: "KNXIPSecureDeviceAuthenticationCode",
		hashes: []string{
			"$knx-ip-secure-device-authentication-code$*3033*fa7c0d787a9467c209f0a6e7cf16069ed704f3959dce19e45d7935c0a91bce41*f927640d9bbe9a4b0b74dd3289ad41ec",
		},
		want: "KNX IP Secure - Device Authentication Code",
	},
	{
		name: "Keccak224",
		hashes: []string{
			"e1dfad9bafeae6ef15f5bbb16cf4c26f09f5f1e7870581962fc84636",
		},
		want: "Keccak-224",
	},
	{
		name: "Keccak256",
		hashes: []string{
			"203f88777f18bb4ee1226627b547808f38d90d3e106262b5de9ca943b57137b6",
		},
		want: "Keccak-256",
	},
	{
		name: "Keccak384",
		hashes: []string{
			"5804b7ada5806ba79540100e9a7ef493654ff2a21d94d4f2ce4bf69abda5d94bf03701fe9525a15dfdc625bfbd769701",
		},
		want: "Keccak-384",
	},
	{
		name: "Keccak512",
		hashes: []string{
			"2fbf5c9080f0a704de2e915ba8fdae6ab00bbc026b2c1c8fa07da1239381c6b7f4dfd399bf9652500da723694a4c719587dd0219cb30eabe61210a8ae4dc0b03",
		},
		want: "Keccak-512",
	},
	{
		name: "KeePass1AESWithoutKeyfile",
		hashes: []string{
			"$keepass$*1*50000*0*375756b9e6c72891a8e5645a3338b8c8*82afc053e8e1a6cfa39adae4f5fe5e59f545a54d6956593d1709b39cacd7f796*c698fbfc7d1b71431d10611e2216ab21*24a63140f4eb3bfd7d59b7694eea38d1d93a43bc3af989755d2b326286c4d510*1*192*1a65072f436e9da0c9e832eca225a04ab78821b55d9f550860ade2ef8126a2c4050cf4d033374abd3dac6d0c5907c6cbb033643b203825c12e6c9853b5ac17a4809559fe723e01b4a2ab87cc83c8ba7ee4a757b8a0cf1674106f21f6675cba12064443d65436650df10ea0923c4cadfd4bfe341a6f4fa23a1a67f7d12a489fc5410ef6db9f6607905de491d3b3b915852a1b6c231c96366cbdee5ea9bd7f73ffd2f7a579215528ae1bf0ea540947ebfe39ca84bc6cbeded4f8e8fb6ed8f32dd5",
		},
		want: "KeePass 1 AES / without keyfile",
	},
	{
		name: "KeePass1TwofishWithKeyfile",
		hashes: []string{
			"$keepass$*1*6000*1*31c087828b0bb76362c10cae773aacdf*6d6c78b4f82ecbcd3b96670cf490914c25ea8c31bc3aeb3fc56e65fac16d721f*a735ec88c01816bc66200c8e17ee9110*08334be8523f4b69bd4e2328db854329bfc81e2ea5a46d8ccf3bccf7c03d879d*1*1360*f1e2c6c47f88c2abf4e79dbe73339b77778233a6c7d7f49f6b7d5db6a4885ff33585e221f5e94e8f7cc84ddcbe9c61a3d40c4f503a4ec7e91edca5745454588eebb4f0dc4d251c0d88eb5fae5d5b651d16e56ef830f412cb7fccf643de4963b66852d3a775489b5abb394b6fa325c3dbb4a55dd06d44c5fc911f1305e55accf0dc0eb172788f5400aab3c867cc6c5ddb7cd3e57bb78a739416985a276825171f5a19750dede055aa3e5fca9b11e3606beae97d68e593631a2efd88cdeb9f43b5ac1d1d9f0164f0fb022ea44a4a48061629c83d8f5bc594e3655ee684102fe706d1e96178bb805105fe1c5326c951401a6e7c9a0b8b572e7b74c3fb25e8700a2e0e70b4621ae3878805397ea1b873ea5218fdaa4fc5d11cdf7ea3579601eca3750fa347edc08569b1f51606d35920253f85f33e6a757a585adf079173161af919f7ea0d78ca6ca1513d01855057373c4f9fe22aba1fc4b18708d329500c127b865a528435e9e00d0a80554ae6eaf4d58bf85a959f37d0854b36c782991c36120b41ee2d9905b18d525b6bffef310e90dbfbe9be853614e6559737f1141f725902f59ee02789c6490c16adf0957e36dc4101c57ba35acb4ca9ec60f5585b60e74342921bbc7e56df5ad942b6deb7936532439b1dae39b9709cf282239c57b434d6f65ba277012ccddce32a217964f974c16f96d8b078ceaad43de9f3d5309279843f2f347ad8ae6eab3a998bb99a421b22b806e2f2302f9dcf3ba54e3d3f1ee64ef3b202194912eec202c2f44847ad5293b03b6b22df35f505670a79219efc399c6a4fa3fd4be7953e5df9baf94101c0a7036b82b6950ab2b722e38aec47bf1c7ffb4e82f43b9ca18d2a8b0b2a7b92015b01d07a429d2660902185cf143f871ff49dde73acf7c3bfd9c124733bd90ffe0fd1cc9090d56dd70bd62f9df1bfa4748ea3438f669d5691c61ec7fbc9d53ab4d8c2dda2cf203f7a5a7fac72eb2efe1d9a27b8c5b14e07a55c530dfd7b7c69dcf478590b7b364f5379f92a0762be0005c4cbc5285d7828248159286fe6d29c02c7de04e96e737a2d30ce75ff774982433f75ca16f09ad668e5b13f0a2e84886773d8fff67f71c1a9dab13f78e5b2da9b1eed9ab2208934a6da7eab32b3e8da1599d6cfa7e9c19ad8efc85dd9a2a4b95832c435381c2fe7e44c58045ce91e40d58c36924b38b19cbafd696bac8761229de9099ce31ee1c93a98aa0cb2a7c60b71b7f1998690e5eae623827727cfe7e8eed94ffc927a1e15aac32292daccda4f0d35383ce87f7e872fc3fe8f01f4a44de4f7b76257abc9c056ab8ae0d96d2dc3a154408c28a2e7befbd515cb5013cbfed31af456ac2b596b5d8095420c411b981d48741dc7ed1e8de4e428bd5e5a553348e2890b1ed12b7dc88261ab921a12da43e6344bbb4a0e0ce2b84c2d1d6c1f51b88202743433ac24340ae00cf27d43346240f4dc5e35ec29fcf1bf6de3bcc09ee8db3f49c3b6615bd8796bbe2cf4b914766779408e772123d9e51cc92ed5dedafa427fd767198cb97674eded4e4df84716aec75cbe7a54620c283fa60780be3cd66ea4167f46cdea1506be92a5102317c8ab8be097c993d82bd831818fe7cb1fbfecc3432d93e0f6d36da8a65ed15c78e623d59980be7ff54bdb1786de2ca9e7a11f0fe067db9ec42ade3bbaad10adae5ea77ba76fa2d0723a35891bde91da540a58e343c23afa9e22b38a66171eb9dbbd55f9e0f014e9de3943388fe0990cc801bbb978c02bf680b3c63a747e22a6317440c40e6844987e936c88c25f49e601ec3486ab080165b5e01dbee47a0a385dfba22ec5ed075f94052bdddabde761bbcc79852402c5b22ded89af4c602922099e37d71b7f87f4ffa614b4ca106fca6b062cba350be1fd12c6812db82f3e02a81e42*1*64*bbc3babf62557aa4dfba705e24274e1aebf43907fe12f52eaf5395066f7cbdba",
		},
		want: "KeePass 1 Twofish / with keyfile",
	},
	{
		name: "KeePass2AESWithoutKeyfile",
		hashes: []string{
			"$keepass$*2*6000*222*a279e37c38b0124559a83fa452a0269d56dc4119a5866d18e76f1f3fd536d64d*7ec7a06bc975ea2ae7c8dcb99e826a308564849b6b25d858cbbc78475af3733f*d477c849bf2278b7a1f626c81e343553*38c8ec186141c2705f2bcb334a730933ed3b0ee11391e1100fbaf429f6c99078*1ada85fe78cf36ab0537562a787dd83e446f13cd3d9a60fd495003de3537b702",
		},
		want: "KeePass 2 AES / without keyfile",
	},
	{
		name: "Keepass2AESWithKeyfile",
		hashes: []string{
			"$keepass$*2*6000*222*15b6b685bae998f2f608c909dc554e514f2843fbac3c7c16ea3600cc0de30212*c417098b445cfc7a87d56ba17200836f30208d38f75a4169c0280bab3b10ca2a*0d15a81eadccc58b1d3942090cd0ba66*57c4aa5ac7295a97da10f8b2f2d2bfd7a98b0faf75396bc1b55164a1e1dc7e52*2b822bb7e7d060bb42324459cb24df4d3ecd66dc5fc627ac50bf2d7c4255e4f8*1*64*aaf72933951a03351e032b382232bcafbeeabc9bc8e6988b18407bc5b8f0e3cc",
		},
		want: "Keepass 2 AES / with keyfile",
	},
	{
		name: "Kerberos5etype17PreAuth",
		hashes: []string{
			"$krb5pa$17$hashcat$HASHCATDOMAIN.COM$a17776abe5383236c58582f515843e029ecbff43706d177651b7b6cdb2713b17597ddb35b1c9c470c281589fd1d51cca125414d19e40e333",
		},
		want: "Kerberos 5, etype 17, Pre-Auth",
	},
	{
		name: "Kerberos5etype17TGSREPAES128CTSHMACSHA196",
		hashes: []string{
			"$krb5tgs$17$user$realm$ae8434177efd09be5bc2eff8$90b4ce5b266821adc26c64f71958a475cf9348fce65096190be04f8430c4e0d554c86dd7ad29c275f9e8f15d2dab4565a3d6e21e449dc2f88e52ea0402c7170ba74f4af037c5d7f8db6d53018a564ab590fc23aa1134788bcc4a55f69ec13c0a083291a96b41bffb978f5a160b7edc828382d11aacd89b5a1bfa710b0e591b190bff9062eace4d26187777db358e70efd26df9c9312dbeef20b1ee0d823d4e71b8f1d00d91ea017459c27c32dc20e451ea6278be63cdd512ce656357c942b95438228e",
		},
		want: "Kerberos 5, etype 17, TGS-REP (AES128-CTS-HMAC-SHA1-96)",
	},
	{
		name: "Kerberos5etype18PreAuth",
		hashes: []string{
			"$krb5pa$18$hashcat$HASHCATDOMAIN.COM$96c289009b05181bfd32062962740b1b1ce5f74eb12e0266cde74e81094661addab08c0c1a178882c91a0ed89ae4e0e68d2820b9cce69770",
		},
		want: "Kerberos 5, etype 18, Pre-Auth",
	},
	{
		name: "Kerberos5etype18TGSREPAES256CTSHMACSHA196",
		hashes: []string{
			"$krb5tgs$18$user$realm$8efd91bb01cc69dd07e46009$7352410d6aafd72c64972a66058b02aa1c28ac580ba41137d5a170467f06f17faf5dfb3f95ecf4fad74821fdc7e63a3195573f45f962f86942cb24255e544ad8d05178d560f683a3f59ce94e82c8e724a3af0160be549b472dd83e6b80733ad349973885e9082617294c6cbbea92349671883eaf068d7f5dcfc0405d97fda27435082b82b24f3be27f06c19354bf32066933312c770424eb6143674756243c1bde78ee3294792dcc49008a1b54f32ec5d5695f899946d42a67ce2fb1c227cb1d2004c0",
		},
		want: "Kerberos 5, etype 18, TGS-REP (AES256-CTS-HMAC-SHA1-96)",
	},
	{
		name: "Kerberos5etype23ASREP",
		hashes: []string{
			"$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac",
		},
		want: "Kerberos 5, etype 23, AS-REP",
	},
	{
		name: "Kerberos5etype23ASREQPreAuth",
		hashes: []string{
			"$krb5pa$23$user$realm$salt$4e751db65422b2117f7eac7b721932dc8aa0d9966785ecd958f971f622bf5c42dc0c70b532363138363631363132333238383835",
		},
		want: "Kerberos 5, etype 23, AS-REQ Pre-Auth",
	},
	{
		name: "Kerberos5etype23TGSREP",
		hashes: []string{
			"$krb5tgs$23$*user$realm$test/spn*$63386d22d359fe42230300d56852c9eb$891ad31d09ab89c6b3b8c5e5de6c06a7f49fd559d7a9a3c32576c8fedf705376cea582ab5938f7fc8bc741acf05c5990741b36ef4311fe3562a41b70a4ec6ecba849905f2385bb3799d92499909658c7287c49160276bca0006c350b0db4fd387adc27c01e9e9ad0c20ed53a7e6356dee2452e35eca2a6a1d1432796fc5c19d068978df74d3d0baf35c77de12456bf1144b6a750d11f55805f5a16ece2975246e2d026dce997fba34ac8757312e9e4e6272de35e20d52fb668c5ed",
		},
		want: "Kerberos 5, etype 23, TGS-REP",
	},
	{
		name: "LM",
		hashes: []string{
			"299bd128c1101fd6",
		},
		want: "LM",
	},
	{
		name: "LastPassLastPassSniffed",
		hashes: []string{
			"a2d1f7b7a1862d0d4a52644e72d59df5:500:lp@trash-mail.com",
		},
		want: "LastPass + LastPass sniffed",
	},
	{
		name: "LineageIIC4",
		hashes: []string{
			"0x35a28484c552747441d8fefe33a98f8f",
		},
		want: "Lineage II C4",
	},
	{
		name: "LinkedIn",
		hashes: []string{
			"b89eaac7e61417341b710b727768294d0e6a277b",
		},
		want: "LinkedIn",
	},
	{
		name: "LinuxKernelCryptoAPI24",
		hashes: []string{
			"$cryptoapi$9$2$03000000000000000000000000000000$00000000000000000000000000000000$d1d20e91a8f2e18881dc79369d8af761",
		},
		want: "Linux Kernel Crypto API (2.4)",
	},
	{
		name: "LotusNotesDomino5",
		hashes: []string{
			"3dd2e1e5ac03e230243d58b8c5ada076",
		},
		want: "Lotus Notes/Domino 5",
	},
	{
		name: "LotusNotesDomino6",
		hashes: []string{
			"(GDpOtD35gGlyDksQRxEU)",
		},
		want: "Lotus Notes/Domino 6",
	},
	{
		name: "LotusNotesDomino8",
		hashes: []string{
			"(HsjFebq0Kh9kH7aAZYc7kY30mC30mC3KmC30mCluagXrvWKj1)",
		},
		want: "Lotus Notes/Domino 8",
	},
	{
		name: "MD2",
		hashes: []string{
			"fcdcaaa9794d753db7da35230ef5dd7a",
		},
		want: "MD2",
	},
	{
		name: "MD4",
		hashes: []string{
			"afe04867ec7a3845145579a95f72eca7",
		},
		want: "MD4",
	},
	{
		name: "MD5",
		hashes: []string{
			"8743b52063cd84097a65d1633f5c74f5",
		},
		want: "MD5",
	},
	{
		name: "MSOffice2007",
		hashes: []string{
			"$office$*2007*20*128*16*411a51284e0d0200b131a8949aaaa5cc*117d532441c63968bee7647d9b7df7d6*df1d601ccf905b375575108f42ef838fb88e1cde",
		},
		want: "MS Office 2007",
	},
	{
		name: "MSOffice2010",
		hashes: []string{
			"$office$*2010*100000*128*16*77233201017277788267221014757262*b2d0ca4854ba19cf95a2647d5eee906c*e30cbbb189575cafb6f142a90c2622fa9e78d293c5b0c001517b3f5b82993557",
		},
		want: "MS Office 2010",
	},
	{
		name: "MSOffice2013",
		hashes: []string{
			"$office$*2013*100000*256*16*7dd611d7eb4c899f74816d1dec817b3b*948dc0b2c2c6c32f14b5995a543ad037*0b7ee0e48e935f937192a59de48a7d561ef2691d5c8a3ba87ec2d04402a94895",
		},
		want: "MS Office 2013",
	},
	{
		name: "MSOffice2016SheetProtection",
		hashes: []string{
			"$office$2016$0$100000$876MLoKTq42+/DLp415iZQ==$TNDvpvYyvlSUy97UOLKNhXynhUDDA7H8kLql0ISH5SxcP6hbthdjaTo4Z3/MU0dcR2SAd+AduYb3TB5CLZ8+ow==",
		},
		want: "MS Office 2016 - SheetProtection",
	},
	{
		name: "MSOffice<=2003$0$1MD5RC4Collider#1",
		hashes: []string{
			"$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2",
		},
		want: "MS Office <= 2003 $0/$1, MD5 + RC4, collider #1",
	},
	{
		name: "MSOffice<=2003$0$1MD5RC4Collider#2",
		hashes: []string{
			"$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2:91b2e062b9",
		},
		want: "MS Office <= 2003 $0/$1, MD5 + RC4, collider #2",
	},
	{
		name: "MSOffice<=2003$3SHA1RC4Collider#1",
		hashes: []string{
			"$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd",
		},
		want: "MS Office <= 2003 $3, SHA1 + RC4, collider #1",
	},
	{
		name: "MSOffice<=2003$3SHA1RC4Collider#2",
		hashes: []string{
			"$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd:b8f63619ca",
		},
		want: "MS Office <= 2003 $3, SHA1 + RC4, collider #2",
	},
	{
		name: "MSOffice<=2003MD5RC4Oldoffice$0Oldoffice$1",
		hashes: []string{
			"$oldoffice$1*04477077758555626246182730342136*b1b72ff351e41a7c68f6b45c4e938bd6*0d95331895e99f73ef8b6fbc4a78ac1a",
		},
		want: "MS Office <= 2003 MD5 + RC4, oldoffice$0, oldoffice$1",
	},
	{
		name: "MSOffice<=2003SHA1RC4Oldoffice$3Oldoffice$4",
		hashes: []string{
			"$oldoffice$3*83328705222323020515404251156288*2855956a165ff6511bc7f4cd77b9e101*941861655e73a09c40f7b1e9dfd0c256ed285acd",
		},
		want: "MS Office <= 2003 SHA1 + RC4, oldoffice$3, oldoffice$4",
	},
	{
		name: "MSAzureSyncPBKDF2HMACSHA256",
		hashes: []string{
			"v1;PPH1_MD4,84840328224366186645,100,005a491d8bf3715085d69f934eef7fb19a15ffc233b5382d9827910bc32f3506",
		},
		want: "MS-AzureSync PBKDF2-HMAC-SHA256",
	},
	{
		name: "MSSQL2000",
		hashes: []string{
			"0x01002702560500000000000000000000000000000000000000008db43dd9b1972a636ad0c7d4b8c515cb8ce46578",
		},
		want: "MSSQL (2000)",
	},
	{
		name: "MSSQL2005",
		hashes: []string{
			"0x010018102152f8f28c8499d8ef263c53f8be369d799f931b2fbe",
		},
		want: "MSSQL (2005)",
	},
	{
		name: "MSSQL20122014",
		hashes: []string{
			"0x02000102030434ea1b17802fd95ea6316bd61d2c94622ca3812793e8fb1672487b5c904a45a31b2ab4a78890d563d2fcf5663e46fe797d71550494be50cf4915d3f4d55ec375",
		},
		want: "MSSQL (2012, 2014)",
	},
	{
		name: "MangosWebEnhancedCMS",
		hashes: []string{
			"cd3b0e89c86962d1240361a3e7474cd2dc029f87",
		},
		want: "MangosWeb Enhanced CMS",
	},
	{
		name: "MediaWiki",
		hashes: []string{
			"$A$5f4dcc3b5aa765d61d8327deb882cf99",
		},
		want: "MediaWiki",
	},
	{
		name: "MediaWikiBType",
		hashes: []string{
			"$B$56668501$0ce106caa70af57fd525aeaf80ef2898",
		},
		want: "MediaWiki B type",
	},
	{
		name: "MetaMaskWallet",
		hashes: []string{
			"$metamask$h0c2mQBGgnhlJ4EWMhdAAZhHlFeZNVlAEwOHQHaEBhY=$q9de9oljOBLWBQRtk9Ugog==$FyaooZR89c3APBYH290LhPdyCsiqrkmRqd6QsJF5io5yqFZa2SWoNsaz12QncB8kTjko02XWdMcg8GmaEagAENRcP0pfov24LNbAbwT/6x5TdcU1C3CKjWnEBTa+AxBxGh8XfYUfN2Edoje6Gt9Gs2A5YYDizdQGzkxpjZTL30QD9NPz1P/k1nfgTcitFUpCsYlcOCUTVPILO5mjzO6eiKmojY3ylhp2vv1HLpls1RfC8UFebJzByRePGuOGX2DzXQztijLOn2tcABlKy9IsOOfbi3rDJtXXESQYZLYJQTXBpGl6S0vgIb4g4WXnX17QW+5Wkm6XXei/GDM4kc/sBTyBJukYr3DayquKR7y07fj3h5M1X1+95qN+RU59n3WKRAl6N8NX7AIOdWTKYBL5DbTOWsW/XDyxnCqBxf/v4bmxWxEMq0jvIs0QyFwL9k6f7jN6OynAOHlrooMrFO8rothyflgW6Q0diwtaBncoQqm/S8Bcbvnijxm0MJy1eST/7jOetv8Okkl5+88Pko3CrqqIIC4TDybak9z8fc3HTl6r6PYa12SsO0X94Fcm50Yf1ejMhqBFLaSzvUq652Yd0JEv4LQ0XYyJWIvJ7/17sl3YZBIGWSdq8oIYm4SlBHENk5xA5VHT3tp8KlolsSgHsHT9vk2aSsCIEJLezq0j+Qogptonn3sDC4jz6KVSyIZW2D4v1I4958dZcWou/OMQD1qGPR7GWOpQW2JrsS+mT05yy5s4LSEV3/w7SzIvpAOfbHrebbw44FI1CrwAyTMc8o/irdJql4jDwaVbRjlLD+Ps4GuzkRhZilN627/+w81uVlX3seM6nUuvHILP/hIXjlPof86ucSqZli5Gnunxivj8qtMRZ4A5gIW9VuOzCbC1qNonW+MD+L2IKxgTEp6svK6y3z59SFMrIjDKszF2fh3BmaoRzbwIxntQq5fzo7YQa9oPmPHHME+VRACC86vpZL2/IDU5TWGYLvw8NA5NcOpw4QKhn7SaXb0iOCmPNCbNh3HlQNNA5nA4KZvIB7kDZa7GUtZqDO5iAmrrOw1ZfE5SzKQshlc5QfVNNpuwJCp7m2UKFePU7bws13tV2arhtIRBjMDz1ncmpyDtiXqaoRHtxoo/ldqutwbZIRuou5G/ydTZLBWMVyorlHyx/Bd3to1ne9WCm6nmUAUJoPcsBb20I3Mm3rYlNrV6iHbHtKirwJjl944SY9WNJqvCMORA3AijLWLteeyKQhsp1o7O30w/Rz+kI3vtcyUiUtudjH5ryjL/I6P6+HVokuiG7dZZiiMJRC0/537AvFt9925MZvC3hPucxKjOyDx0niA2i3Z/cpvTXC1GgIfHfCMwdnX/phjiHR5wASaI6eHTKYq3opSwqKvTDeomIlRViu12LoX0vThRxl9kKu9uCC2NB4fflOYYu5Okp48xVVMt3Fv2B58pT4jRn5VddPBx9qgV0NlBe1Fo8PWhe+HFIjXCFaLkr1OTy6G71ECv3yjQGTTPbrdqHUE8ZpPTFz3iPutCS3GvJmdMDVkWi0q8ASWH7yR/NmHYv9wNIDEh034tiv769rk82xKP+qJ0xCPr6mFVypIf9dmpmN26G4C9Hw6PD36VrVTSEoXFvXj7+LPfUwvRYQ0vZoqQRPvnIkpIqy71fkrbBlFmBdzZMP9lM79ZF2m9PnddDvqGLSL5M0EzrwRCnon6Wq1i5nsE1ruJCL2leg2EcVYQoUg3ADHpGInx7BTrOnOOVxxnbRUqMki1SegqV2CBARcXbRXXH8yaPSzrrHS4QQvCI8eQ8Yu8RObvAxez2N5cFaupudbGk5v/SWPsSHO2HxerZfD+yeW6PUrZjE8v5tgmA3w8iZzfHiEzQX8cx+Qvd1UnlxIrJTXWoNSYz9OjS+oCkvZc/G9Zmy4oKl0agTA8dVs1XETMlCEPHuxubxzLt8ldr37EiWJZcAfPg+KY9B9DtDjcPu0hsa9Zpf5GyL39IoeOgL3Kom/RgY9eIBEUcdlSPGkvFLGKcquALER3014sI9m4KmzDdyUmcK5mgdsYYBKdl7+YrLnMPi3aB2/9YK3roUpABE5TpjEd61tPXi3Qgqu8t01tUGxelX9CPucDJVfaP6YMWN18p2AMgqhbcDZo20mNrf/+NFE1v80LWuXllbMmBhqGszElb7RmZXC3P1NwEp42hTRGYDlK904omxxKj/ICNqwhOwEddO3ktwFegAeBq2BqS4/88MOMUfpZgLGK9Jx/+U9/WCn0EAO3H/fdK2ulB/eoBK4fGQnup9aAl7m05nnYBFCLXhAZzzcDVC0+6GRRshjbTdqfMUgEM7b+lTK7A7Wf+fpAU/42M7FB6f1qExKmLaXCbi2Ss0r6bfiZblwiizy7huRnyuWk3KKcIp6HK+8opPY4uNnXG9tm44cjLQvhWZA3DhP0HyNYYyPazAciH/4NTha9NsWXDZOdKym8iXIQ+F46a0B2bq7SJa6XbmJaM3ej3HNQ0NYz2jx2R5Y9nYMywUtxPzVKCCspQdqFnM810V9cMHV9wCD4lmE3DFrZ+2ulcOJ41KLOW0e/WMP4z7Tt6VJXxpp6mz0omwt3j15KtCGUoviaA5oDbBWc+uMd6L4i9g/0L041EncR8dm19Tws7sQW3LrbNikJ3EPJEk7Gs3szxT/IoJd3n1MVCjT5KBmutusSjUIdjKjci7S3WYWjAsQayR7unPUaDCzl3eUOEReMs4DL37kh0lEQHIsV1L01CqFVh1rqhyQ+Dazxh1ZOA9vB+TH67sOkc0dpn0T+TqNlJPZVrQhyknECDJlY8z46D63TYekfpockhf2FFW9QMyHWnIWBNkFu/fdz9usCD3o6fkooSc/nzJlKXgMulyceEo5FerIxyrPvB8X5scVaad+Cnd3ILBbEed7avxY/CT+8n+ZeEcUN9I9PD3/gsdnPxU0z27hVdiid/JVqjQstKK73U9bqPpc8RSunga7vU6tU0y8IKf2P2xcLxwp+l9iabz4nNB+ployIZUFggOVpQNvLrgMegwnPf7adONRoZQIC2Xcqgc+k/FdYbwrpqdjKIm78PDqg67b5b3m0FeHTq9YWPSa3YBwRbhSvfDChfAu6u9FQSTndfN9RVJPiHJHFgUryB2QnaSArKxT7lUlSXPpHcA7+wMl1oWzmft20EeHM2tm6/nzB1yuqI5tid+DI6tt2ivtvdFyhwSWAsdcnp7tgSL7gX4kvAC/oUY8zLBjSOFY=",
		},
		want: "MetaMask Wallet",
	},
	{
		name: "MicrosoftOutlookPST",
		hashes: []string{
			"$pst$815b338f",
		},
		want: "Microsoft Outlook PST",
	},
	{
		name: "MinecraftXAuth",
		hashes: []string{
			"cb5ef15b400cef07addb37e00e2cdd6d1b508a2a26f0befcb0f9d8fd03c1d67be1690eba2287c4f76a590f2feae654ce5aee9943a23babb8e56381fe3214a48ad8754a1fd9eb",
		},
		want: "Minecraft(xAuth)",
	},
	{
		name: "MongoDBServerKeySCRAMSHA1",
		hashes: []string{
			"$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=",
		},
		want: "MongoDB ServerKey SCRAM-SHA-1",
	},
	{
		name: "MongoDBServerKeySCRAMSHA256",
		hashes: []string{
			"$mongodb-scram$*1*dXNlcg==*15000*qYaA1K1ZZSSpWfY+yqShlcTn0XVcrNipxiYCLQ==*QWVry9aTS/JW+y5CWCBr8lcEH9Kr/D4je60ncooPer8=",
		},
		want: "MongoDB ServerKey SCRAM-SHA-256",
	},
	{
		name: "MozillaKey3DB",
		hashes: []string{
			"$mozilla$*3DES*b735d19e6cadb5136376a98c2369f22819d08c79*2b36961682200a877f7d5550975b614acc9fefe3*f03f3575fd5bdbc9e32232316eab7623",
		},
		want: "Mozilla key3.db",
	},
	{
		name: "MozillaKey4DB",
		hashes: []string{
			"$mozilla$*AES*5add91733b9b13310ea79a4b38de5c3f797c3bf1*54c17e2a8a066cbdc55f2080c5e9f02ea3954d712cb34b4547f5186548f46512*10000*040e4b5a00f993e63f67a34f6cfc5704*eae9c6c003e6d1b2aa8aa21630838808",
		},
		want: "Mozilla key4.db",
	},
	{
		name: "MultiBitClassicKeyMD5",
		hashes: []string{
			"$multibit$1*e5912fe5c84af3d5*5f0391c219e8ef62c06505b1f6232858f5bcaa739c2b471d45dd0bd8345334de",
		},
		want: "MultiBit Classic .key (MD5)",
	},
	{
		name: "MultiBitClassicWalletScrypt",
		hashes: []string{
			"$multibit$3*16384*8*1*7523cb5482e81b81*91780fd49b81a782ab840157a69ba7996d81270eaf456c850f314fc1787d9b0b",
		},
		want: "MultiBit Classic .wallet (scrypt)",
	},
	{
		name: "MultiBitHDScrypt",
		hashes: []string{
			"$multibit$2*2e311aa2cc5ec99f7073cacc8a2d1938*e3ad782e7f92d66a3cdfaec43a46be29*5d1cabd4f4a50ba125f88c47027fff9b",
		},
		want: "MultiBit HD (scrypt)",
	},
	{
		name: "MurmurHash",
		hashes: []string{
			"b69e7687:05094309",
		},
		want: "MurmurHash",
	},
	{
		name: "MurmurHash3",
		hashes: []string{
			"23e93f65:00000000",
		},
		want: "MurmurHash3",
	},
	{
		name: "MyBB12IPB2InvisionPowerBoard",
		hashes: []string{
			"8d2129083ef35f4b365d5d87487e1207:47204",
		},
		want: "MyBB 1.2+, IPB2+ (Invision Power Board)",
	},
	{
		name: "MySQL$A$SHA256Crypt",
		hashes: []string{
			"$mysql$A$005*F9CC98CE08892924F50A213B6BC571A2C11778C5*625479393559393965414D45316477456B484F41316E64484742577A2E3162785353526B7554584647562F",
		},
		want: "MySQL $A$ (sha256crypt)",
	},
	{
		name: "MySQLCRAMSHA1",
		hashes: []string{
			"$mysqlna$1c24ab8d0ee94d70ab1f2e814d8f0948a14d10b9*437e93572f18ae44d9e779160c2505271f85821d",
		},
		want: "MySQL CRAM (SHA1)",
	},
	{
		name: "MySQL323",
		hashes: []string{
			"7196759210defdc0",
		},
		want: "MySQL323",
	},
	{
		name: "MySQL41MySQL5",
		hashes: []string{
			"fcf7c1b8749cf99d88e5f34271d636178fb5d130",
		},
		want: "MySQL4.1/MySQL5",
	},
	{
		name: "NTHashFreeBSDVariant",
		hashes: []string{
			"$3$$8846f7eaee8fb117ad06bdd830b7586c",
		},
		want: "NTHash(FreeBSD Variant)",
	},
	{
		name: "NTLM",
		hashes: []string{
			"b4b9b02e6f09a9bd760f388b67351e2b",
		},
		want: "NTLM",
	},
	{
		name: "NetNTLMv1NetNTLMv1ESS",
		hashes: []string{
			"u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c",
		},
		want: "NetNTLMv1 / NetNTLMv1+ESS",
	},
	{
		name: "NetNTLMv1NetNTLMv1ESSNT",
		hashes: []string{
			"::5V4T:ada06359242920a500000000000000000000000000000000:0556d5297b5daa70eaffde82ef99293a3f3bb59b7c9704ea:9c23f6c094853920",
		},
		want: "NetNTLMv1 / NetNTLMv1+ESS (NT)",
	},
	{
		name: "NetNTLMv2",
		hashes: []string{
			"admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030",
		},
		want: "NetNTLMv2",
	},
	{
		name: "NetNTLMv2NT",
		hashes: []string{
			"0UL5G37JOI0SX::6VB1IS0KA74:ebe1afa18b7fbfa6:aab8bf8675658dd2a939458a1077ba08:010100000000000031c8aa092510945398b9f7b7dde1a9fb00000000f7876f2b04b700",
		},
		want: "NetNTLMv2 (NT)",
	},
	{
		name: "OpenDocumentFormatODF11SHA1Blowfish",
		hashes: []string{
			"$odf$*0*0*1024*16*bff753835f4ea15644b8a2f8e4b5be3d147b9576*8*ee371da34333b69d*16*a902eff54a4d782a26a899a31f97bef4*0*dae7e41fbc3a500d3ce152edd8876c4f38fb17d673ee2ac44ef1e0e283622cd2ae298a82d8d98f2ea737247881fc353e73a2f535c6e13e0cdc60821c1a61c53a4b0c46ff3a3b355d7b793fad50de15999fc7c1194321d1c54316c3806956c4a3ade7daabb912a2a36398eba883af088b3cb69b43365d9ba9fce3fb0c1524f73947a7e9fc1bf3adb5f85a367035feacb5d97c578b037144c2793f34aa09dcd04bdaa455aee0d4c52fe377248611dd56f2bd4eb294673525db905f5d905a28dec0909348e6bf94bcebf03ddd61a48797cd5728ce6dbb71037b268f526e806401abcf495f6edd0b5d87118671ec690d4627f86a43e51c7f6d42a75a56eec51204d47e115e813ed4425c97b16b195e02ce776c185194b9de43ae89f356e29face016cb393d6fb93af8ea305d921d5592dd184051ac790b9b90266f52b8d53ce1cb1d762942d6d5bbd0e3821be21af9fa6874ba0c60e64f41d3e5b6caca1c53b575afdc5d8f6a3edbf874dbe009c6cb296466fe9637aed4aed8a43a95ea7d26b4090ad33d4ee7a83844b0893e8bc0f04944205fb9576cb5720f019028cd75ca9ac47b3e5fa231354d74135564df43b659cfaea7e195c4a896e0e0e0c85dc9ce3a9ce9ba552bc2a6dbac4901c19558818e1957ed72d78662bb5ba53475ca584371f1825ae0c92322a4404e63c2baad92665aac29b5c6f96e1e6338d48fb0aef4d0b686063974f58b839484f8dcf0a02537cba67a7d2c4de13125d74820cb07ec72782035af1ea6c4db61c77016d1c021b63c8b07adb4e8510f5c41bbc501f60f3dd16462399b52eb146787e38e700147c7aa23ac4d5d22d9d1c93e67a01c92a197d4765cbf8d56a862a1205abb450a182913a69b8d5334a59924f86fb3ccd0dcfe7426053e26ba26b57c05f38d85863fff1f81135b0366e8cd8680663ae8aaf7d005317b849d5e08be882708fa0d8d02d47e89150124b507c34845c922b95e62aa0b3fef218773d7aeb572c67b35ad8787f31ecc6e1846b673b8ba6172223176eabf0020b6aa3aa71405b40b2fc2127bf9741a103f1d8eca21bf27328cdf15153f2f223eff7b831a72ed8ecacf4ea8df4ea44f3a3921e5a88fb2cfa355ece0f05cbc88fdd1ecd368d6e3b2dfabd999e5b708f1bccaeebb296c9d7b76659967742fe966aa6871cbbffe710b0cd838c6e02e6eb608cb5c81d066b60b5b3604396331d97d4a2c4c2317406e48c9f5387a2c72511d1e6899bd450e9ca88d535755bcfddb53a6df118cd9cdc7d8b4b814f7bc17684d8e5975defaa25d06f410ed0724c16b8f69ec3869bc1f05c71483666968d1c04509875dadd72c6182733d564eb1a7d555dc34f6b817c5418626214d0b2c3901c5a46f5b20fddfdf9f71a7dfd75b9928778a3f65e1832dff22be973c2b259744d500a3027c2a2e08972eaaad4c5c4ec871",
		},
		want: "Open Document Format (ODF) 1.1 (SHA-1, Blowfish)",
	},
	{
		name: "OpenDocumentFormatODF12SHA256AES",
		hashes: []string{
			"$odf$*1*1*100000*32*751854d8b90731ce0579f96bea6f0d4ac2fb2f546b31f1b6af9a5f66952a0bf4*16*2185a966155baa9e2fb597298febecbc*16*c18eaae34bcbbe9119be017fe5f8b52d*0*051e0f1ce0e866f2b771029e03a6c7119aad132af54c4e45824f16f61f357a40407ab82744fe6370c7b2346075fcd4c2e58ab244411b3ab1d532a46e2321599ef13c3d3472fc2f14d480d8c33215e473da67f90540279d3ef1f62dde314fa222796046e496c951235ddf88aa754620b7810d22ebc8835c90dce9276946f52b8ea7d95d2f86e4cc725366a8b3edacc2ce88518e535991a5f84d5ea8795dc02bfb731b5f202ecaf7d4b245d928c4248709fcdf3fba2acf1a08be0c1eee7dbeda07e8c3a6983565635e99952b8ad79d31c965f245ae90b5cc3dba6387898c66fa35cad9ac9595c41b62e68efcdd73185b38e220cf004269b77ec6974474b03b7569afc3b503a2bf8b2d035756f3f4cb880d9ba815e5c944508a0bde214076c35bf0e0814a96d21ccaa744c9056948ed935209f5c7933841d2ede3d28dd84da89d477d4a0041ce6d8ddab891d929340db6daa921d69b46fd5aee306d0bcef88c38acbb495d0466df7e2f744e3d10201081215c02db5dd479a4cda15a3338969c7baec9d3d2c378a8dd30449319b149dc3b4e7f00996a59fcb5f243d0df2cbaf749241033f7865aefa960adfeb8ebf205b270f90b1f82c34f80d5a8a0db7aec89972a32f5daa2a73c5895d1fced01b3ab8e576bd2630eff01cad97781f4966d4b528e1b15f011f28ae907a352073c96b203adc7742d2b79b2e2f440b17e7856ae119e08d15d8bdf951f6d4a3f9b516da2d9a8f9dd93488f8e0119f3da19138ab787f0d7098a652cccd914aa0ff81d375bd6a5a165acc936f591639059287975cfc3ca4342e5f9501b3249a76d14e56d6d56b319e036bc0449ac7b5afa24ffbea11babed8183edf8d4fdca1c3f0d23bfd4a02797627d556634f1a9304e03737604bd86f6b5a26aa687d6df73383e0f7dfe62a131e8dbb8c3f4f13d24857dd29d76984eac6c45df7428fc79323ffa1f4e7962d705df74320141ed1f16d1ad483b872168df60315ffadbfa1b7f4afaed8a0017421bf5e05348cb5c707a5e852d6fee6077ec1c33bc707bcd97b7701ee05a03d6fa78b0d31c8c97ea16e0edf434961bd5cc7cbb7eb2553730f0405c9bd21cee09b3f7c1bc57779fdfc15f3935985737a1b522004c4436b631a39a66e8577a03f5020e6aa41952c0662c8c57f66caa483b47af38b8cb5d457245fd3241749e17433e6f929233e8862d7c584111b1991b2d6e94278e7e6e1908cee5a83d94c78b75a84a695d25aeb9fdde72174fe6dd75e8d406671f44892a385a4a1e249f61ebc993e985607423a0a5742e668d52c1ebf5cecae7c2b7908f4627b92ec49354a9ccff8cb5763ad074a00e65a485a41bf4c25ce7e6fae49358a58547b1c0ca79713e297310c0a367c3de196f1dd685ca4be643bdf1e4f6b034211d020557e37a3b6614d061010b4a3416b6b279728c245d3322",
		},
		want: "Open Document Format (ODF) 1.2 (SHA-256, AES)",
	},
	{
		name: "OpenCart",
		hashes: []string{
			"6e36dcfc6151272c797165fce21e68e7c7737e40:472433673",
		},
		want: "OpenCart",
	},
	{
		name: "OpenEdgeProgressEncode",
		hashes: []string{
			"lebVZteiEsdpkncc",
		},
		want: "OpenEdge Progress Encode",
	},
	{
		name: "OracleHTypeOracle7+",
		hashes: []string{
			"7A963A529D2E3229:3682427524",
		},
		want: "Oracle H: Type (Oracle 7+)",
	},
	{
		name: "OracleSTypeOracle11+",
		hashes: []string{
			"ac5f1e62d21fd0529428b84d42e8955b04966703:38445748184477378130",
		},
		want: "Oracle S: Type (Oracle 11+)",
	},
	{
		name: "OracleTTypeOracle12+",
		hashes: []string{
			"78281A9C0CF626BD05EFC4F41B515B61D6C4D95A250CD4A605CA0EF97168D670EBCB5673B6F5A2FB9CC4E0C0101E659C0C4E3B9B3BEDA846CD15508E88685A2334141655046766111066420254008225",
		},
		want: "Oracle T: Type (Oracle 12+)",
	},
	{
		name: "OracleTransportationManagementSHA256",
		hashes: []string{
			"otm_sha256:1000:1234567890:S5Q9Kc0ETY6ZPyQU+JYY60oFjaJuZZaSinggmzU8PC4=",
		},
		want: "Oracle Transportation Management (SHA256)",
	},
	{
		name: "PBKDF2Cryptacular",
		hashes: []string{
			"$p5k2$2710$oX9ZZOcNgYoAsYL-8bqxKg==$AU2JLf2rNxWoZxWxRCluY0u6h6c=",
		},
		want: "PBKDF2(Cryptacular)",
	},
	{
		name: "PBKDF2DwayneLitzenberger",
		hashes: []string{
			"$p5k2$2710$.pPqsEwHD7MiECU0$b8TQ5AMQemtlaSgegw5Je.JBE3QQhLbO",
		},
		want: "PBKDF2(Dwayne Litzenberger)",
	},
	{
		name: "PBKDF2HMACMD5",
		hashes: []string{
			"md5:1000:MTg1MzA=:Lz84VOcrXd699Edsj34PP98+f4f3S0rTZ4kHAIHoAjs=",
		},
		want: "PBKDF2-HMAC-MD5",
	},
	{
		name: "PBKDF2HMACSHA1",
		hashes: []string{
			"sha1:1000:MzU4NTA4MzIzNzA1MDQ=:19ofiY+ahBXhvkDsp0j2ww==",
		},
		want: "PBKDF2-HMAC-SHA1",
	},
	{
		name: "PBKDF2HMACSHA256",
		hashes: []string{
			"sha256:1000:MTc3MTA0MTQwMjQxNzY=:PYjCU215Mi57AYPKva9j7mvF4Rc5bCnt",
		},
		want: "PBKDF2-HMAC-SHA256",
	},
	{
		name: "PBKDF2HMACSHA256PHP",
		hashes: []string{
			"sha256:1000:BK6lxgbbN23j3ArZSmcFWd6HbQFmkfF3:iDi/NefIjKWog5dEvWfuQDQ+s4Ei6K5I",
		},
		want: "PBKDF2-HMAC-SHA256(PHP)",
	},
	{
		name: "PBKDF2HMACSHA512",
		hashes: []string{
			"sha512:1000:ODQyMDEwNjQyODY=:MKaHNWXUsuJB3IEwBHbm3w==",
		},
		want: "PBKDF2-HMAC-SHA512",
	},
	{
		name: "PBKDF2SHA256Werkzeug",
		hashes: []string{
			"pbkdf2:sha256$1tNyTG7rtLMYuIos$fa8b1915621cc59f3967a9747e083ad9b59934806336a6a24afff926044334e1",
		},
		want: "PBKDF2-SHA256(Werkzeug)",
	},
	{
		name: "PDF1113Acrobat24",
		hashes: []string{
			"$pdf$1*2*40*-1*0*16*51726437280452826511473255744374*32*9b09be05c226214fa1178342673d86f273602b95104f2384b6c9b709b2cbc058*32*0000000000000000000000000000000000000000000000000000000000000000",
		},
		want: "PDF 1.1 - 1.3 (Acrobat 2 - 4)",
	},
	{
		name: "PDF1113Acrobat24Collider#1",
		hashes: []string{
			"$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000",
		},
		want: "PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #1",
	},
	{
		name: "PDF1113Acrobat24Collider#2",
		hashes: []string{
			"$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000:6a8aedccb7",
		},
		want: "PDF 1.1 - 1.3 (Acrobat 2 - 4), collider #2",
	},
	{
		name: "PDF1416Acrobat58",
		hashes: []string{
			"$pdf$2*3*128*-1028*1*16*da42ee15d4b3e08fe5b9ecea0e02ad0f*32*c9b59d72c7c670c42eeb4fca1d2ca15000000000000000000000000000000000*32*c4ff3e868dc87604626c2b8c259297a14d58c6309c70b00afdfb1fbba10ee571",
		},
		want: "PDF 1.4 - 1.6 (Acrobat 5 - 8)",
	},
	{
		name: "PDF1416Acrobat58UserAndOwnerPass",
		hashes: []string{
			"$pdf$2*3*128*-3904*1*16*631ed33746e50fba5caf56bcc39e09c6*32*5f9d0e4f0b39835dace0d306c40cd6b700000000000000000000000000000000*32*842103b0a0dc886db9223b94afe2d7cd63389079b61986a4fcf70095ad630c24",
		},
		want: "PDF 1.4 - 1.6 (Acrobat 5 - 8) - user and owner pass",
	},
	{
		name: "PDF17Level3Acrobat9",
		hashes: []string{
			"$pdf$5*5*256*-1028*1*16*20583814402184226866485332754315*127*f95d927a94829db8e2fbfbc9726ebe0a391b22a084ccc2882eb107a74f7884812058381440218422686648533275431500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000",
		},
		want: "PDF 1.7 Level 3 (Acrobat 9)",
	},
	{
		name: "PDF17Level8Acrobat1011",
		hashes: []string{
			"$pdf$5*6*256*-1028*1*16*21240790753544575679622633641532*127*2d1ecff66ea354d3d34325a6503da57e03c199c21b13dd842f8d515826054d8d2124079075354457567962263364153200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000",
		},
		want: "PDF 1.7 Level 8 (Acrobat 10 - 11)",
	},
	{
		name: "PHPS",
		hashes: []string{
			"$PHPS$34323438373734$5b07e065b9d78d69603e71201c6cf29f",
		},
		want: "PHPS",
	},
	{
		name: "PHPassPortableHash",
		hashes: []string{
			"$P$984478476IagS59wHZvyQMArzfx58u.",
			"$H$984478476IagS59wHZvyQMArzfx58u.",
		},
		want: "PHPass' Portable Hash",
	},
	{
		name: "PKCS#8PrivateKeysPBKDF2HMACSHA13DESAES",
		hashes: []string{
			"$PEM$1$4$f5662bd8383b4b40$2048$2993b585d3fb2e7b235ed13d90f637e2$1232$73984f2cba4d5e1d327a3f5a538a946099976ab865349091a452a838dc6855b6e539f920a078b14d949d8c739ea7ce26769dc0ba1619a9c0ee1864d1cfca9e61ddf6d9582439f2b65d00a3ff57c78d3176e9e88fc12da7acd421b624ba76f3d5f12926a3a9acd82f502d7638cfe2063fb2c773a56299ae1ec2c85641d33f5f8b3edfc6687fa9898325d384b3db7a7686704facb880c3898f69dd353a5d5d136b58a1e00e4711d3a01e0c632a5f3d5eff64c9e88166296b9b26f072a52bdc4893377e247b5cdb052f34e0b5d4de10a5dffe443a03b1a23f1edbcb00361334dbd6a6d31e16887b5290da2f865fbe1fef7b43c8f8f3432815ca860946560cb601ab83d417e6a4734aaf75692195566bde61e04610a9eff752c08f9ff85a48959daa7c65d03a0eca62e92bf10a55fb4834a49745a6c53d9c79d0591cb13cfa54f0d437d001b7924fd9dd69c98aa25e5d3f19649f79913bca827e7636ede04bf7c41ef54c42936b4eb93c75d941853dc7dda42b51ac5e4f5602fe2c3e62f252d28e02398943780598cf2bd41d183425daf34e86099c748eda2d5372029ebd089f619dab327ea728eb90342f2b48cd364e914a6078599afdb22a6fac6b55e1bf28b3284a0edc748b59c2eaa97e35d457d4c049f86fd3fc618c4c52f08776c0efb33011b96ef6f0b0e6ecf6d37dc20da8ab7d9b8154371c8e396d9b89ee02e6e6b013a0985b1f47c91f3b5a9e6c33736840e6044f46be1dbea4ec7730eccc6e993cb522bb220de4ed55156129f821d7df19439ab86990991cfd1992681716b5ff012ffa5519ad0baa01885f77f6a522469979f449232d408379558fcdfe5253371da835e0c77706dfa67ff28b1cd8d7fdf9e386899838532d8e57ec1ed3d31a96ae03f37b976fb6c503cc247113deaa070697728e3b36ce43de051ce13a4df91d22157c6281e8f9a16de007c6dddf03ffc79a9f4cfc3eaddd637a9a902fdba1c9e857a9ccd7c318db17cd40d8b588b5d97c7d03c0404473dd201aa5c6637e952c6299e35374127276b3eb4aeba754f3176fecea1731a0f917dd049fcdab34264a8c635ba90eec941aeb449a7eca263aaec9e46758bdf21caa896adb4652e9564d75c20e296fcdf28cbdeb702a1e7acf2374d24b51e6492b0bcc72a58748666a7278e2cb54fbdb68c6736ceb85dd92cd0465b19a65f7ad47e25658a34c3531db48c37ef279574e1892d80d80f3e9dee385ab65e6a4537f6e318817a785228160939d01632b8269858ce9092359048b09ae8b9c17ceb575216988bbeb91c1b5861c931f21e07d888ceb9b89d89d17608e2d5f0ae66b6e756f1eac9f80e13749f866ea6b741158296d3ced761999ad901a2121e233bf173865b6c0b32d68e6ef1d39bb411a1ee9d4d1cde870645b9922051b31cc0df640fb01d23c613091ba538999254b873fbb5996efdfbde5c933e1b6ef6d1c7d5e1a9bff6800c8625b07aba2c14143c1a33a0661c357e5db59a2f49aab35c13531774fb5b3795ed853d7f4e38910c7eeb3435353e2cfd0c94e61c16c8126928343f86222c5ef320b9e043d3cd357af4e065500f50e6bf9c260ca298bd5507c9498dbcea4ceec834449b7fb7249fdf199f66aa98d0a820b1057df1d67c43f49c6d18c3c902466b2b2b528075489261ef73bf711c7988fed65693798568bed43e4d70a800cd25b1773c455aaa153cea8f7013eae1e8f24c6793f590c8f6a112b46",
		},
		want: "PKCS#8 Private Keys (PBKDF2-HMAC-SHA1 + 3DES/AES)",
	},
	{
		name: "PKCS#8PrivateKeysPBKDF2HMACSHA2563DESAES",
		hashes: []string{
			"$PEM$2$4$ed02960b8a10b1f1$2048$a634c482a95f23bd8fada558e1bac2cf$1232$50b21db4aededb96417a9b88131e6bc3727739b4aa1413417338efaa6a756f27c32db5c339d9c3ba61c746bbe3d6c5e0a023f965e70fb617e78a00890b8c7fc7c9f5e0ab39f35bf58ab40f6ed15441338134d041ca59783437ef681a51132c085abb3830df95e9f94d11da54d61679ca6e40136da96ffe205ce191002458143f03cba3aeca6b22a3f0689d5582b3e6c01baee7a04d875ed44bb84fa0ed0a3aae1ed392645cced385498eef4ec25bf6d1399f1487f3625fad9fee25aabf18edb1ce5e640e834d31251b882601f23c2b2d77a45c84e0fc8a3a42e3ff9f75e7ac815c57a7e943ad803ab3672f85a37c6b92d0813590d47a31788643449dce67f135363a0c14f089629a1274b124539535df5f50df5d4402f7a109738f56467725a8aa3884562c8b4c42c068c3502be86e20ac9c52c0daec22e47dcbefebe902b1dc791ed3cd069c7f9211e43f5a3274450f4b0f0b7c6f59adeca8b39ed130b6cbda7cf98e15bbba21fa1758a28dc2edf2e2f17fc353853dc881458e59184f5a8f6e09456e4d71d90135a8ce67350f7bcb3d900e75585e3a87c0c8482f3917347fcfad4fdb8915991cffd20dae1502d0f69d385244e489e50cc9f24b15a5f9d0b00d62805026db5378b5408d7d719786eb043659a452096736e4a7501548655df83045dc4e86bd3319f2982e6db2bbb239019202cebf2ca68c05b578ba95cef82397b145c80208cd7ffd9b0cd5fc3d0d7ea26401c8e11c28ab8d1a524b884962e7fee597943a5e38137abb8b26a7772f0ad6dad074dcfd0b5794822aa7e43d10cab2c95e63b6459706dc21a1cbbd7ae4c96b40ee4d7039cf84c416cb879b2d30b7ac5e1860dcd2ab5479c39b748f5fd9336934c9c1e8064ffb0906c0c2898479209d1a9c97c3cd1782d7514e94d01b242a371a2df5592d620ebd6e18e63ff24ee8ba182f17e6c578431d738e955a957469e8069a919fd3a15532d460201d4e38ac04ac494b9cde1731d4511bf8faf8420a9de4f8c7d3d721fc30d8c3664683fd91ad3515e97092fb652205fb087890cb594947f5372c9b0b27f08b4b57bf610f777fcf040e6e7b8cedf85113dfd909cbac4b774c7580686f2e1f261898da4c6804d573fb22248005f5e0d3b256a0f3dcb71c47b3d674352bda82c22a513e381f990b6100328185511de9b3352126c5aedb9b0bde15743b42e231ef7227c0fe478044ce69474a740366058f07e56dde7d6089cb76e606482e7ba206355fc0fa180c4a41ae781e4723120e3d5a1dd40224db2c959ecbc9bce88bfeed64082d07b111e88a2d8a6a6fe097c9a298a6c3f76beb5b3b5aecedbbbcd404aac8fd25c069c747338ca0c81e6b63d87fc4f0bc18a86b721e3a16e9875741e0313057de8476ee84e36efe557dc33a7d23a9426f2e359781147607ad79235c9d7846320fe2d963fac79a5c92ff3067595273931174d2173f63cfceb9f62a873e7c240d3c260bcfb02b2697911321a72455cacc6929133d0af2cdf6d59a63293ac508786a4850267f90993fff3b6c07bbf3af0e3c08638148101ae1495da3360614866e238c4f60ca00f615877be80cc708da5ea1c30032acffd0e55429ba29dca409349d901a49831db44c1e58b7530b383d3f7e1cac79200cad9bdf87451783f2ffdab09b230aab52b41fa42fdd9f1f05a3dda0fa16b011c51e330d044adf394bbbb7fa25efc860f3082e42824be3b96943afbe641fe6bb",
		},
		want: "PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)",
	},
	{
		name: "PKZIPCompressedMultiFile",
		hashes: []string{
			"$pkzip2$3*1*1*0*8*24*a425*8827*d1730095cd829e245df04ebba6c52c0573d49d3bbeab6cb385b7fa8a28dcccd3098bfdd7*1*0*8*24*2a74*882a*51281ac874a60baedc375ca645888d29780e20d4076edd1e7154a99bde982152a736311f*2*0*e3*1c5*eda7a8de*0*29*8*e3*eda7*5096*1455781b59707f5151139e018bdcfeebfc89bc37e372883a7ec0670a5eafc622feb338f9b021b6601a674094898a91beac70e41e675f77702834ca6156111a1bf7361bc9f3715d77dfcdd626634c68354c6f2e5e0a7b1e1ce84a44e632d0f6e36019feeab92fb7eac9dda8df436e287aafece95d042059a1b27d533c5eab62c1c559af220dc432f2eb1a38a70f29e8f3cb5a207704274d1e305d7402180fd47e026522792f5113c52a116d5bb25b67074ffd6f4926b221555234aabddc69775335d592d5c7d22462b75de1259e8342a9ba71cb06223d13c7f51f13be2ad76352c3b8ed*$/pkzip2$",
		},
		want: "PKZIP (Compressed Multi-File)",
	},
	{
		name: "PKZIPCompressed",
		hashes: []string{
			"$pkzip2$1*1*2*0*e3*1c5*eda7a8de*0*28*8*e3*eda7*5096*a9fc1f4e951c8fb3031a6f903e5f4e3211c8fdc4671547bf77f6f682afbfcc7475d83898985621a7af9bccd1349d1976500a68c48f630b7f22d7a0955524d768e34868880461335417ddd149c65a917c0eb0a4bf7224e24a1e04cf4ace5eef52205f4452e66ded937db9545f843a68b1e84a2e933cc05fb36d3db90e6c5faf1bee2249fdd06a7307849902a8bb24ec7e8a0886a4544ca47979a9dfeefe034bdfc5bd593904cfe9a5309dd199d337d3183f307c2cb39622549a5b9b8b485b7949a4803f63f67ca427a0640ad3793a519b2476c52198488e3e2e04cac202d624fb7d13c2*$/pkzip2$",
		},
		want: "PKZIP (Compressed)",
	},
	{
		name: "PKZIPMixedMultiFileChecksumOnly",
		hashes: []string{
			"$pkzip2$8*1*1*0*8*24*a425*8827*3bd479d541019c2f32395046b8fbca7e1dca218b9b5414975be49942c3536298e9cc939e*1*0*8*24*2a74*882a*537af57c30fd9fd4b3eefa9ce55b6bff3bbfada237a7c1dace8ebf3bb0de107426211da3*1*0*8*24*2a74*882a*5f406b4858d3489fd4a6a6788798ac9b924b5d0ca8b8e5a6371739c9edcfd28c82f75316*1*0*8*24*2a74*882a*1843aca546b2ea68bd844d1e99d4f74d86417248eb48dd5e956270e42a331c18ea13f5ed*1*0*8*24*2a74*882a*aca3d16543bbfb2e5d2659f63802e0fa5b33e0a1f8ae47334019b4f0b6045d3d8eda3af1*1*0*8*24*2a74*882a*fbe0efc9e10ae1fc9b169bd060470bf3e39f09f8d83bebecd5216de02b81e35fe7e7b2f2*1*0*8*24*2a74*882a*537886dbabffbb7cac77deb01dc84760894524e6966183b4478a4ef56f0c657375a235a1*1*0*8*24*eda7*5096*40eb30ef1ddd9b77b894ed46abf199b480f1e5614fde510855f92ae7b8026a11f80e4d5f*$/pkzip2$",
		},
		want: "PKZIP (Mixed Multi-File Checksum-Only)",
	},
	{
		name: "PKZIPMixedMultiFile",
		hashes: []string{
			"$pkzip2$3*1*1*0*0*24*3e2c*3ef8*0619e9d17ff3f994065b99b1fa8aef41c056edf9fa4540919c109742dcb32f797fc90ce0*1*0*8*24*431a*3f26*18e2461c0dbad89bd9cc763067a020c89b5e16195b1ac5fa7fb13bd246d000b6833a2988*2*0*23*17*1e3c1a16*2e4*2f*0*23*1e3c*3f2d*54ea4dbc711026561485bbd191bf300ae24fa0997f3779b688cdad323985f8d3bb8b0c*$/pkzip2$",
		},
		want: "PKZIP (Mixed Multi-File)",
	},
	{
		name: "PKZIPUncompressed",
		hashes: []string{
			"$pkzip2$1*1*2*0*1d1*1c5*eda7a8de*0*28*0*1d1*eda7*5096*1dea673da43d9fc7e2be1a1f4f664269fceb6cb88723a97408ae1fe07f774d31d1442ea8485081e63f919851ca0b7588d5e3442317fff19fe547a4ef97492ed75417c427eea3c4e146e16c100a2f8b6abd7e5988dc967e5a0e51f641401605d673630ea52ebb04da4b388489901656532c9aa474ca090dbac7cf8a21428d57b42a71da5f3d83fed927361e5d385ca8e480a6d42dea5b4bf497d3a24e79fc7be37c8d1721238cbe9e1ea3ae1eb91fc02aabdf33070d718d5105b70b3d7f3d2c28b3edd822e89a5abc0c8fee117c7fbfbfd4b4c8e130977b75cb0b1da080bfe1c0859e6483c42f459c8069d45a76220e046e6c2a2417392fd87e4aa4a2559eaab3baf78a77a1b94d8c8af16a977b4bb45e3da211838ad044f209428dba82666bf3d54d4eed82c64a9b3444a44746b9e398d0516a2596d84243b4a1d7e87d9843f38e45b6be67fd980107f3ad7b8453d87300e6c51ac9f5e3f6c3b702654440c543b1d808b62f7a313a83b31a6faaeedc2620de7057cd0df80f70346fe2d4dccc318f0b5ed128bcf0643e63d754bb05f53afb2b0fa90b34b538b2ad3648209dff587df4fa18698e4fa6d858ad44aa55d2bba3b08dfdedd3e28b8b7caf394d5d9d95e452c2ab1c836b9d74538c2f0d24b9b577*$/pkzip2$",
		},
		want: "PKZIP (Uncompressed)",
	},
	{
		name: "PKZIPMasterKey",
		hashes: []string{
			"f1eff5c0368d10311dcfc419",
		},
		want: "PKZIP Master Key",
	},
	{
		name: "PKZIPMasterKey6ByteOptimization",
		hashes: []string{
			"f1eff5c0368d10311dcfc419",
		},
		want: "PKZIP Master Key (6 byte optimization)",
	},
	{
		name: "PalshopCMS",
		hashes: []string{
			"a05938cc2e475e64937c057e33bbba227c4d634cfbfbbfc7c5c",
		},
		want: "Palshop CMS",
	},
	{
		name: "PeopleSoft",
		hashes: []string{
			"uXmFVrdBvv293L9kDR3VnRmx4ZM=",
		},
		want: "PeopleSoft",
	},
	{
		name: "PeopleSoftPSTOKEN",
		hashes: []string{
			"b5e335754127b25ba6f99a94c738e24cd634c35a:aa07d396f5038a6cbeded88d78d1d6c907e4079b3dc2e12fddee409a51cc05ae73e8cc24d518c923a2f79e49376594503e6238b806bfe33fa8516f4903a9b4",
		},
		want: "PeopleSoft PS_TOKEN",
	},
	{
		name: "PostgreSQL",
		hashes: []string{
			"a6343a68d964ca596d9752250d54bb8a:postgres",
		},
		want: "PostgreSQL",
	},
	{
		name: "PostgreSQLCRAMMD5",
		hashes: []string{
			"$postgres$postgres*f0784ea5*2091bb7d4725d1ca85e8de6ec349baf6",
		},
		want: "PostgreSQL CRAM (MD5)",
	},
	{
		name: "PostgreSQLMD5",
		hashes: []string{
			"md54e9c5b51bd070727b0ed21956cb68de7",
		},
		want: "PostgreSQL MD5",
	},
	{
		name: "PrestaShop",
		hashes: []string{
			"810e3d12f0f10777a679d9ca1ad7a8d9:M2uZ122bSHJ4Mi54tXGY0lqcv1r28mUluSkyw37ou5oia4i239ujqw0l",
		},
		want: "PrestaShop",
	},
	{
		name: "PunBB",
		hashes: []string{
			"4a2b722cc65ecf0f7797cdaea4bce81f66716eef:653074362104",
		},
		want: "PunBB",
	},
	{
		name: "PythonPasslibPBKDF2SHA1",
		hashes: []string{
			"$pbkdf2$131000$r5WythYixPgfQ2jt3buXcg$8Kdr.QQEOaZIXNOrrru36I/.6Po",
		},
		want: "Python passlib pbkdf2-sha1",
	},
	{
		name: "PythonPasslibPBKDF2SHA256",
		hashes: []string{
			"$pbkdf2-sha256$29000$x9h7j/Ge8x6DMEao1VqrdQ$kra3R1wEnY8mPdDWOpTqOTINaAmZvRMcYd8u5OBQP9A",
		},
		want: "Python passlib pbkdf2-sha256",
	},
	{
		name: "PythonPasslibPBKDF2SHA512",
		hashes: []string{
			"$pbkdf2-sha512$25000$LyWE0HrP2RsjZCxlDGFMKQ$1vC5Ohk2mCS9b6akqsEfgeb4l74SF8XjH.SljXf3dMLHdlY1GK9ojcCKts6/asR4aPqBmk74nCDddU3tvSCJvw",
		},
		want: "Python passlib pbkdf2-sha512",
	},
	{
		name: "QNXEtcShadowMD5",
		hashes: []string{
			"@m@75f6f129f9c9e77b6b1b78f791ed764a@8741857532330050",
		},
		want: "QNX /etc/shadow (MD5)",
	},
	{
		name: "QNXEtcShadowSHA256",
		hashes: []string{
			"@s@0b365cab7e17ee1e7e1a90078501cc1aa85888d6da34e2f5b04f5c614b882a93@5498317092471604",
		},
		want: "QNX /etc/shadow (SHA256)",
	},
	{
		name: "QNXEtcShadowSHA512",
		hashes: []string{
			"@S@715df9e94c097805dd1e13c6a40f331d02ce589765a2100ec7435e76b978d5efc364ce10870780622cee003c9951bd92ec1020c924b124cfff7e0fa1f73e3672@2257314490293159",
		},
		want: "QNX /etc/shadow (SHA512)",
	},
	{
		name: "RACF",
		hashes: []string{
			"$racf$*USER*FC2577C6EBE6265B",
		},
		want: "RACF",
	},
	{
		name: "RAR3hp",
		hashes: []string{
			"$RAR3$*0*45109af8ab5f297a*adbf6c5385d7a40373e8f77d7b89d317",
		},
		want: "RAR3-hp",
	},
	{
		name: "RAR3pCompressed",
		hashes: []string{
			"$RAR3$*1*ad56eb40219c9da2*834064ce*32*13*1*eb47b1abe17a1a75bce6c92ab1cef3f4126035ea95deaf08b3f32a0c7b8078e1*33",
		},
		want: "RAR3-p (Compressed)",
	},
	{
		name: "RAR3pUncompressed",
		hashes: []string{
			"$RAR3$*1*e54a73729887cb53*49b0a846*16*14*1*34620bcca8176642a210b1051901921e*30",
		},
		want: "RAR3-p (Uncompressed)",
	},
	{
		name: "RAR5",
		hashes: []string{
			"$rar5$16$74575567518807622265582327032280$15$f8b4064de34ac02ecabfe9abdf93ed6a$8$9843834ed0f7c754",
		},
		want: "RAR5",
	},
	{
		name: "RIPEMD128",
		hashes: []string{
			"cdf26213a150dc3ecb610f18f6b38b46",
		},
		want: "RIPEMD-128",
	},
	{
		name: "RIPEMD160",
		hashes: []string{
			"012cb9b334ec1aeb71a9c8ce85586082467f7eb6",
		},
		want: "RIPEMD-160",
	},
	{
		name: "RIPEMD256",
		hashes: []string{
			"02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d",
		},
		want: "RIPEMD-256",
	},
	{
		name: "RIPEMD320",
		hashes: []string{
			"22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8",
		},
		want: "RIPEMD-320",
	},
	{
		name: "RSADSAECOpenSSHPrivateKeys$0$",
		hashes: []string{
			"$sshng$0$8$7532262427635482$1224$e1b1690703b83fd0ab6677c89a00dfce57fc2f345ebd2b2993bf0d8bb267449d08839213dc234dd23c7a181077e00080ced2700a161c4352ce5574b9758926f09106157715b6d756cf6dd844e473c6bb3c2b591cdbf684394a49935f7d62bcc324c1392aee499e3d6235db0556d27adc6e35ef4654ee5fc72e60dff605484e75c6fd6ae29cb476f8a658dbcce9f9591a9dad023f6d9aa223c3d56261e056c5cafa93438937e0762b989cd10e6280a09488be07423c549514ff9686338e72dbe6bdc5015944739a9f183cacf04c1c141dc8c8d8aa8636c85a6c0578a5983ed33d5ff5ee6a66a54d86defd1c4f9d6a59446861bf4cc7bd667bc92b9d328c154f442d1d03d4d370dcc065a1d5420c5b71e4c35a457e11a0c9f489636559a2ac53bb4cfee2b0058f8a9d1ccc38a844ee0d1ff5d6938427bf24d6e4c69f10e6ebce9187d51e867ac3b362b9c6149712e8378a9ac91d1aab1a7a5f088ddbdead0cc754c30961b7a71284b5c6658f7219632de6007d5145a1ae062f807234230ff73a3436ce28ae3bfa0f880d1e49ec8a288da18db14905bc7a7b061a51c429876db81ad528efb469ba2bf46c7344aadc7d082efc83ede3894bf6b1738151e642f6f60a41069ad862d2f4f8d55733bd6d85086d1d9bb1913a9d4680ea0b49f712c590a3c18b91ef745b9bdf461af67879d94f9672de4abe0b7d2e4efba1f8bb6ffbb4a095742d5cff0e225b1b5e166854bb9821e4283d97f80855c81efea1eb3e7881a6049186650bfbf68f30302c069883668e373c12ce9a39de8d7c1be22a717d9c74410c45093aae03c5de8cc0ec662fe3bb81bf952e17b854001bcad9b36cab2f473a609878a419b735c66f3732bd5540fb1cba9fe081f87cecf63a6243cd2049dfa25a763ef2e0633bfb13a411207d8ca1c8f3c0c30b8a7583436cad7bd8c28ba625b9c53dc280b314671b0a55d75a28d3b21de250e3c554b86ca5d32821ab912c6607687c4dc5b3214216a7409621ce6fb89bd5309a7dd8ec9ae4b751bdfb6b5d12d733a89d87722dbdb1b15df5463241f0f56c401e095ea5dee07c0ded1f11ffbd7c93a41add0cfd8c57b44f255fdfd1929cd7d068d6cf951ba8ab0d718996fec10aaa26a4314d4c1272f744adf3c7e4d710ae171c072a7c61c2b020a445cf32be3083d3bc62083f2385bbae4fadddf8714258b996abd574638891bb918e877fdef3a4856b910999a6dc9dbd13c0e938825cd895c96d39cb86bb283a53fac7090c71a9320c6a34af309d2218af64c895f5eff8eee28cf94e7a7437a0922d83bfa39f08bb40e354d9ace07aa586a446dc217ede98b6ca9637545cc11ef56732fc9cd3dc06e459d868137b75d39a87e6721a95f2b84e57c94ef703486a2857821e497b990c95080015d825b6dc63d666f66cfa35912e607c3b650d81dc98c0c53322796ff9249cdfe7a375e1d01607816a85bb43f3969767a9aaed07161344e714d7e875b40f3524f95e476e605dbd2ac51e36075701fa93b66f36470796ebf5d35690a297e19729f9ac59d98622e3ad3e45a2914bdd2b807446c8b430e54c1a607fd25a69bf469a61d2e3bc3697b786c047bc60dbeabe6372d71e9b7c9787bb2559c663a011f864ecf32793e65f4bdd76370d99f602ddcbc7e5aa7d2749f36e8d0f209a378782882bc06ee5b5014c2a6248469f0fe0fc5369383db0bc898c0760b8c40fe20342fa5b",
		},
		want: "RSA/DSA/EC/OpenSSH Private Keys ($0$)",
	},
	{
		name: "RSADSAECOpenSSHPrivateKeys$1$3$",
		hashes: []string{
			"$sshng$1$16$14987802644369864387956120434709$1232$ffa56007ed83e49fdc439c776a9dec9656521385073bf71931a2c6503c93917e560cc98940c8cdcf2c709265e9ba20783a3bacc63423a98e40ea8999182613e1f5a80084719ca0e5c390299de1ea947df41f2ff1489bddfe13c6128612c5c82b7fc1ef5105ea28adda7b415729c66fb6cbc4b6b51ef518f74e1971f88e0cfabd69e8c4270678e360149ce15716fef4736df296a20d2607ef269a3c69896fc423683d6057e00064f84e04caf4d4663b51b307cfb1d1dbd6b3bf67764a08847c7b83fa5544e6a1e950f16acda8c8bac30675bc3cea9c7e06790ddc7cd1e4177b93bdd0d9edf9cdceb4a4444b437d967acdb92274a7b10d9cd1073ab4e9b5dd468aabe1f40a02b2e51f19840798c2311b625037eba5f0a0256638b42577385f4d4c730a9cedf4e244ce74656a21bf16756857866433dbb1feff9c4323d234d4235b72ed5a3adc3a6c9bae373472d64b7882d1762911326f330cb42d8ab7931f1ad2de56c4e6e8a6e838108cf9a2728ffa356796f63d94723b1d0aad5b4fcea16ab0730e7553804ad9ffb6ecdbdd925fca05ca1c076ed09a30df8a5add44a43c36b92248dc8dd4605bc2ee557e6e4438abf9ea7d047f764c55a5ba46a41719b9c55e54ad5fbfce6a89b9283c163d8464ecdda5aaf113d038b659950b8c79e87abad019eb77535cc8e63f760a4c87ca344a563475361766df718519b1b7e4b3ab511952fcc9b011f1d8971f9261509139b739afcc2c9acd006ee714dffc8c9a4df0d54770d70c8c28c27cdf9ee7301fd64530ef0ec3eb044fb891b193a7aaa9158625ed9f5a842c86ed09e5377d90a69aea4c5fd321bc3ac9b2a0d34509a5de0b72ac3f81304895c4381e01136b1e8654cec20c220c0ac6a1300f031ffc68ddeab554279024c122589b91556feef394a1663b42fb8460af5fe881cb1cd4984b84be75125411b1d3fc236dd81f99b872aad511d28944e91d2f8853f11be85b6930a15b4d0b3d215d76416970ade5726979c1d737980fb68ecb03d1196a69f4013dd2e296a75a4c69664b0162cb8b22af18c536a8ce51f39b1282f2fe07e6b034627f075cfb20dffee62817aabeea60befea1ac93ba608d957e4030e41be7bc55275bc4037300f6ba736370eb7c9240629853c95f9304b7ffd26a10d55ae735fa943e29aa9ed437b61955fc16cde9ea7a3658d831bdbc38befa45cec80da9ccb6d21da83ff666e32d7c5c0ca0ade2cd685407ee701c1c707fc5c80b22f3af42ac1353fcdc09a459086434db7c78792decdc91572363478a14d1256346a9ac6336b8183ed6252106aa546dd092c0bbb464cdb44ae165d67d1be135877587de3bbbd02b5ef6473f125366f6dae0536ebbe18ab8de8ce2ef3d26d6dd400319e7d07ae276b081e94446e9a72877cf23e9ba52406b1842e3a0dcf7bbdc63a1336b894be475613cc917eb47724f64e621bfc3053d7423e3e2fb141a3368dc8881fa20e040e9a6bc2e7348e923e4c20e506566b8663bf7d557e792cbe4adffcf9c520d58565d77f6bf1c9ed5fa3209f8047765d01b9c264e97a3ef9ff90766ad69a4f508041e168bf0f7419e54ec88bdc4c858231cdba60774a27cc459cd65b46e26a620a43033788c6e2ee8916670568d6e6c700515f2cbca3eef62028ce75245cf8f99cd6e0ba7839a7b335c797a06ff80571950ebec2fccebb89265025b3250e4a5c9c3a62f471324556fc4db044cebe97f62c86913",
		},
		want: "RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)",
	},
	{
		name: "RSADSAECOpenSSHPrivateKeys$4$",
		hashes: []string{
			"$sshng$4$16$01684556100059289727957814500256$1232$b04d45fdfdf02a9ca91cbc9c53f9e59956822c72c718929aca9251cffd9ac48e48c490b7b6b6043df3a70cf5fbcc2f358b0e8b70d39155c93032b0fd79ec68f6cb8b7de8422ec95cb027a9eaacc453b0b99b5d3f8d6771d6b95b0242a1d8664de8598e8d6b6d6ee360fda5ae0106061a79e88ef2eef98a000b638f8fdc367155ec2d1120b366f74f0933efe5d174e7107db29dc8fb592b22b9837114415d78036c116b2d31b2080c7159442f2d1a61900f5ae4913548c8e7fc716dd4f812bc7e57b2dd5d3f56c6ae0e91c3bc2897d9341cb282d86b915d43cf20ad16fbd2056104529576142354a430281f5e458923ef8014ff9950351798bfcbbcb66cb98bb2cccea48c134b0e05e978d4308c82617869b207f0ed7b227893f2cdde2d6b6a98246de8a2494d5e018a84724780fbe8d1fa91c922908d18ccffbbbbc81e6578fe8bb5c8596a8cf689f3f12b810dee95887e12439e487313229a37913e3cd12bddba3bac94fab03aad8607f6034fa87f7a7a2ac74d0c0a6e6bc905f569221861e1e388cf379cda799d7b56eac58440d17fe97fa68a537d34317376c00dfa9a99e04725a0d2fcf27ee50463e725813c96fe2eed16de59e8a6944d903e11f7923d57ae6d4a1f8085ce19f4d180f13027806f3965fdf875ea092f103f28a5f42f356254958fa7eb0bca2389a6ad4e305640cc64501e6b16330b063037b1cf6fe64131f308e50d9d1dc687ffa487681941084ff21cb54c1b5903b7a78d9913595fa0124f1dde49b1bee2ea83837efe34e2cd6051a4a7a1437eaa84ad332ffd9946b952ed634948789d9541820a0f9c6f44ab6d3cad645743c76c54e79bfdc4fb8e43a0fd7d871baea98e78131bc530b6d736fa1ec5ac70438609497ab2ff8d516146b4b1b3488791cb84dccc0096b570e2ffb3a93cccefec0af7ce616a64466d2d4196941ba9e051dc00ed05e963a7b4a286973ee0b5df4fd92dfb0b229b10730d454832d945c6a596862212d109ce78ac14ffb5d775548b2f3e2ae4be059a24465cc10b7c810f8cc3db7cb327619cc104ebea575ac097d20701dc623f7aa893b785cc20851f3972390e00ab3355655f7d5bea323832c17d8e078e917843ef7fcaca349366092b6743bf7511d5fceb2d992fbd18574be532365be41ad80a114704a64a7aefdf98c907aa10e4d5c547dd8d21647ea9d5c975fe1b24525d94c3eb03e071742fd5f09f22da669b649fac9f87d8cf16c475d006421f69a9b2d5c4037ccc9bf9f0aa0e7df8ac5fcb0d88a528833f9640799026d2fe8694fa1a0307c5f24002172464b290bedd85667800edbff2f1de7119e5b65730a24922e42d53ef28b0a59817a298426dc72e29a85e59e3d777b19eb934bcd620a903aff72927cdbe7253f77694ab0ef970378b4347f6166ca2a40b23cc31970f0cbefd08d2d72bf2c3961d67c73a5a24f75a65e540dc5735520b0d81250af8980ddca3e22a9b25773afd27c76e564ff437d4208df14d802f1d0848390f45924cdd6ced3c9ffb726bb358b334ea0e0481acdd103f2db05f508f62588621d0b8fa274a69eba0d418d85086d9139391f7e28dc54fe9bab801f1fea854f27ad2e5907ae6f9a4b4527d16a8af3c8cbe2c6d82209dc6c7da060da58294eb00380598330c4c19d45581d09e04c0153a8559700b3a8ceab9b8124f84d397356cd9e38e3916afc1f63a3e1dfbc7df8dd0a7d0704e38a0ea523dfc2b9defd5",
		},
		want: "RSA/DSA/EC/OpenSSH Private Keys ($4$)",
	},
	{
		name: "RSADSAECOpenSSHPrivateKeys$5$",
		hashes: []string{
			"$sshng$5$16$52935050547964524511665675049973$1232$febee392e88cea0086b3cdefd3efec8aedb6011ca4ca9884ef9776d09559109c328fd4daef62ea4094a588d90d4617bc0348cc1205ae140e5bdca4e81bf7a8ff4fcc9954d3548ba9a0d143a504750d04d41c455d6100b33dacc5f9a10036ae75be69a81471e945554a52ca12b95640a08f607eab70c4a750dc48917f3c9ee23c537e9b4a49728a9773a999dfd842cf9a38155029ea5d42f617dbec630889d078ffadaf3ff28eed65389a73528f3d0863fffd9a740edd59ca223595e330bca37ac5a003ac556d2b6232f9900fc8654586e73e7b2d83327d61b2fc561a78aacc8aff473bb3d18ddccae87d84de143a8a98550d955d01d4e6074ac62aa0af0bca58a0c53d0d7cf1a26345c1bd3eca7a0c0e711f5c7f942d50bc872be971d0c17dbc5a88f043a937ff5d28c5ef8d8d291e511d070b14a0cc696ee5088a944b113bc7e697cdc793e931c3f0f3a892b44aad1468e6c45becdcaa89febda17fcd5fe6ff430695e04b5b6271e032e3529315367e56337777a5b342c19d3ebc7441ac0f79b93749ad4526b8be0a5cf5756363aac93da6dc19dbfff15bacbbf2dae7a549afdab8e0589321ac0a612576bbfe06fde086075d1244450a3667f793ccc81fd5ccc5b1d08e6f447e3e0cd89b901049bedb1e65b23ede0d8f00ff1c984743b50342c50408e9060ed6a809a7b068972c9542cd91de0767c02a73d192ea600008bf4a6ef339c7f2db767346cc479e61abedb4ba4a67f72e91ac49a2e92bb4bacd97aed0b044c258e2004fa0fb8da3678a57d37187c1246c90a107540161462145fa7307a6d4db34694fb1b090f07bedb9ca0e71aefd3ce5601b87778fd6b66391c3c61d528a5965f91370f52a72f0622620329f96c5dd68561e0f6576f3a2bc5c21a95aed569edc4ed979746b32909178e550907c5f41d7b24480e81a874b931c23f13517ab5f9331f11819d982bf9e5b8a03034b47c8785f8902611eac26716976bccd51d19864f10ee1fbd62f8b0149c22ab06205a20f9f9fcb0a5279552a8923c3ace2e134f6b190653f430c1a4b82f762283028d9c0c8d1a3428731f4f405f40f947f297a43aa3ba2267bbc749a5677da92a63d51d24aa5ca3e9e1d35a8143d7b4bac481f0c56754e980a60cf2d330797fc81f6c6f405760f1257103ac6edf10976c9005f4a261f7aad055400c4f18dc445eb3a403740ad6c58afa4e8edb30fad907488baf0ede2eb3d3687d1e8724dd69c7bd14b90d4f113fc9f84a2c01ab00917f53cd879a4031b1c91a4d4d7d9e712a584959137001d331f6725dca81ea6cc55fac7fc0e8b578dec0983ca98c3789cdf83507e4c3ba056fdcbea26693a313077290d7c6695f4cc6de4848532f0149cc06dbf4c76d02944178520585923b636196ea2cbcacc43950b308fc7929e85de076a2ab65c9bd8ebb0c04c041281178a48d8d2165d315b3e74abf0a38505b71ae5b2a6e7f87861e174cff873a1f61980b53ef3acdd2ea6a25425b162e5dc0bc1aa2992585d2da1625a6593cc2d4fe8c86eeb4df0e27cda54685f7245e5c48063d489e8d93bd5303bebe633139dcdd04afa005d03d1185a64e8711c0b09d9d0b38b35d6ef1b1e35353a7a4396863650a3843c687a00396dd3db53e8d28baf29101abb9f628ba896b091618f24187f6eeb814e4b64130768fb37e89b9b3230e50a7e5aba852a983525c8f193deb1fe27b334cdc3bdfa4c301d04907ee29a848393",
		},
		want: "RSA/DSA/EC/OpenSSH Private Keys ($5$)",
	},
	{
		name: "RSADSAECOpenSSHPrivateKeys$6$",
		hashes: []string{
			"$sshng$6$8$7620048997557487$1224$13517a1204dc69528c474ef5cbb02d548698771f2a607c04ea54eb92f13dedba0f2185d2884b4db0c95ce6432856108ea2db858be443e0f8004ffcd60857e4ff1e42b17f056998ec5f96806a06e39cc6e6d7ef4ce8ae62b57b2ec0d0236c35cf4bc00dd6fda45e4788dcca0f0e44dddae1dad2d6e7b705d076f2f8fc5837eec4a002d9633bcad1f395ca8e85e78459abe293451567494d440c3f087bb7fe4d6588018f92ca327dda514a99d7b4b32434da0e3b1bf9344afb2fe29f8d8315a385fe8b81fd4c202c7d82cd9f0bb1600e59762ab6ea1b42e4e299f0a59ce510767e1e1138453d362d0a1aa6680e86b5aa0bd5c62165f4fe7c2867f9533578085adc36739d6c9cf7b36899aac39dcabac8b39194433423e8e18ba28496bbe14dd01231eb5b091ae9de0f7f9ea714c22edac394077fb758fe496e1880571ade399ac229457ddd98577f8a01a036ad3bc8b03a9fb02e26b4b76f6cb676eabe82d1606fca0c5fca62cd1d82c3df1ed58ab4acd4611b2827ebde722bc05e471a427225818aa36dabf5bf1203ccb0ebc8dec097e49f7f948bfe7b939e6d0ff1125b863c033768f588964f8b77ca1e2425751f873f80e5d6a0671f7860cf4a46533585094726c3afe5f7203fa4a01650fa9839772c713a033139cfc6a6e6f7dc62e5844d4c57ef4fc3321bc85d597a54bd6fe37e9e696cf3b5ec66f55232e0964dc5cf880d8a41a9891150618bd9c088fd9824af0d86f817f2c79429c3d56cd6eb41eb6120f9accc10a863f23a2bb6c57d4bd6193f2283ae0215e2e87e672a8438e2550c044fa9556bdb4afc40d8c2752ffbc6c95571756a3c230bb2fa95f519f8da238ef0857ecf860247a8b26e28269f9bad564e7d8bfba2eac9760b52449251cb35e183f5b309a09071535154c6f1013b58f305b544f3589c9eb0e9ac4267a84374a3eab49c53aa9bedbf97f8f19ebc212d8db74ee03554a3514140667fa4ce8e06aad3f32d1b00015be0e8979fe66736018589beee06d6f318851dbe8d9689e70202185d71fc5e5a3d2996ddb8ae1d7718c49855c6f8c43301e0915f324f30d0d9c6a8504a91ad5a7179aafb87ede58598394949910874850994abe815817359152ff6a7c8cc6f19524dfc5e50ddfd038a2275bf809e3c8f05ed3e3137ebd62d91cd3578533787c3847e3c5e07e5a891480e5ceabcf6c344e7bec8b640ab9a03e90b846b35d2f46ba150accef32d2597b064810b15fd54fca6d2b146feabcd05c0b51617ae95e36f6817a62c3ff42c5c2f6f1d20a8a1fd334d3b7d3f83bba057b79d9b5508bb0cb706ba00acb0ab797401fdcfac80b5b6e38e51aec0b38f33ff4690425ca28d88a2e876591521230150b4e20a4a82e50061cee9c0705100bfe5fdbd8ef27aec20387cf32455ef305bce2a91ae6da91fc41376b97149e9b41c901b24811df9272ff09718923b8d94e8e459a164a22b0eca47653f3efcbf08188c5da78cd9fb9eda1761094f9d8bc3d479e9f40c7d79ebaaba2a5c632329f20a9962040ff8f512b42c5f32a8460d87b8e93c6f980a1562c436eea1c8994fbf671dda3c4ccd3c142acfcdde2ab61227289ad408213ac8e22d9ef487f36925f5ba3b8e7e913d25c4a8592c861d13f03b615bc2760aabc61d68db80d35296a3312fdf4b56c0fbee5ab3fea1cf9caf3960a564046939e8002d2dd909db446d85aeae9dd42a33fe28684f722172e6",
		},
		want: "RSA/DSA/EC/OpenSSH Private Keys ($6$)",
	},
	{
		name: "Radmin2",
		hashes: []string{
			"22527bee5c29ce95373c4e0f359f079b",
		},
		want: "Radmin2",
	},
	{
		name: "RedHat389DSLDAPPBKDF2HMACSHA256",
		hashes: []string{
			"{PBKDF2_SHA256}AAAgADkxMjM2NTIzMzgzMjQ3MjI4MDAwNTk5OTAyOTk4NDI2MjkyMzAzNjg0NjQwOTMxNjI3OTMzNjg0MDI0OTY5NTe5ULagRTYpLaUoeqJMg8x9W/DXu+9VTFaVhaYvebYrY+sOqn1ZMRnws22C1uAkiE2tFM8qN+xw5xe7OmCPZ203NuruK4oB33QlsKIEz4ppm0TR94JB9PJx7lIQwFHD3FUNUNryj4jk6UYyJ4+V1Z9Ug/Iy/ylQBJgfs5ihzgxHYZrfp1wUCXFzlZG9mxmziPm8VFnAhaX4+FBAZvLAx33jpbKOwEg7TmwP2VJ8BNFLQRqwYdlqIjQlAhncXH+dqIF9VdM4MonAA0hx76bMvFTP7LF5VO1IqVmcuYz7YG9v4KKRjnvoUUqOj6okUBQTay3EzsdFVnUW1FemYOccJd5q",
		},
		want: "RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)",
	},
	{
		name: "Redmine",
		hashes: []string{
			"1fb46a8f81d8838f46879aaa29168d08aa6bf22d:3290afd193d90e900e8021f81409d7a9",
		},
		want: "Redmine",
	},
	{
		name: "RubyOnRailsRestfulAuthOneRoundNoSitekey",
		hashes: []string{
			"3999d08db95797891ec77f07223ca81bf43e1be2:5dcc47b04c49d3c8e1b9e4ec367fddeed21b7b85",
		},
		want: "Ruby on Rails Restful Auth (one round, no sitekey)",
	},
	{
		name: "RubyOnRailsRestfulAuthentication",
		hashes: []string{
			"d7d5ea3e09391da412b653ae6c8d7431ec273ea2:238769868762:8962783556527653675",
		},
		want: "Ruby on Rails Restful-Authentication",
	},
	{
		name: "SAMLMHashNTHash",
		hashes: []string{
			"5dc82d817ee488fc4afe1b7c07093904:16bafcac2a2558b7aad3b435b51404ee",
		},
		want: "SAM(LM_Hash:NT_Hash)",
	},
	{
		name: "SAPCODVNBBCODE",
		hashes: []string{
			"USER$C8B48F26B87B7EA7",
		},
		want: "SAP CODVN B (BCODE)",
	},
	{
		name: "SAPCODVNBBCODEFromRFCREADTABLE",
		hashes: []string{
			"027642760180$77EC386300000000",
		},
		want: "SAP CODVN B (BCODE) from RFC_READ_TABLE",
	},
	{
		name: "SAPCODVNFGPASSCODE",
		hashes: []string{
			"USER$ABCAD719B17E7F794DF7E686E563E9E2D24DE1D0",
		},
		want: "SAP CODVN F/G (PASSCODE)",
	},
	{
		name: "SAPCODVNFGPASSCODEFromRFCREADTABLE",
		hashes: []string{
			"604020408266$32837BA7B97672BA4E5A00000000000000000000",
		},
		want: "SAP CODVN F/G (PASSCODE) from RFC_READ_TABLE",
	},
	{
		name: "SAPCODVNHPWDSALTEDHASHiSSHA1",
		hashes: []string{
			"{x-issha, 1024}C0624EvGSdAMCtuWnBBYBGA0chvqAflKY74oEpw/rpY=",
		},
		want: "SAP CODVN H (PWDSALTEDHASH) iSSHA-1",
	},
	{
		name: "SCRAMHash",
		hashes: []string{
			"$scram$6400$.Z/znnNOKWUsBaCU$sha-1=cRseQyJpnuPGn3e6d6u6JdJWk.0,sha-256=5GcjEbRaUIIci1r6NAMdI9OPZbxl9S5CFR6la9CHXYc,sha-512=.DHbIm82ajXbFR196Y.9TtbsgzvGjbMeuWCtKve8TPjRMNoZK9EGyHQ6y0lW9OtWdHZrDZbBUhB9ou./VI2mlw",
		},
		want: "SCRAM Hash",
	},
	{
		name: "SHA1Crypt",
		hashes: []string{
			"$sha1$40000$jtNX3nZ2$hBNaIXkt4wBI2o5rsi8KejSjNqIq",
		},
		want: "SHA-1 Crypt",
	},
	{
		name: "SHA1Oracle",
		hashes: []string{
			"f4bda8587b35988da6d362fd692118460eab06d753616c74",
		},
		want: "SHA-1(Oracle)",
	},
	{
		name: "SHA1",
		hashes: []string{
			"b89eaac7e61417341b710b727768294d0e6a277b",
		},
		want: "SHA1",
	},
	{
		name: "SHA2224",
		hashes: []string{
			"e4fa1555ad877bf0ec455483371867200eee89550a93eff2f95a6198",
		},
		want: "SHA2-224",
	},
	{
		name: "SHA2256",
		hashes: []string{
			"127e6fbfe24a750e72930c220a8e138275656b8e5d8f48a98c3c92df2caba935",
		},
		want: "SHA2-256",
	},
	{
		name: "SHA2384",
		hashes: []string{
			"07371af1ca1fca7c6941d2399f3610f1e392c56c6d73fddffe38f18c430a2817028dae1ef09ac683b62148a2c8757f42",
		},
		want: "SHA2-384",
	},
	{
		name: "SHA2512",
		hashes: []string{
			"82a9dda829eb7f8ffe9fbe49e45d47d2dad9664fbb7adf72492e3c81ebd3e29134d9bc12212bf83c6840f10e8246b9db54a4859b7ccd0123d86e5872c1e5082f",
		},
		want: "SHA2-512",
	},
	{
		name: "SHA3224",
		hashes: []string{
			"412ef78534ba6ab0e9b1607d3e9767a25c1ea9d5e83176b4c2817a6c",
		},
		want: "SHA3-224",
	},
	{
		name: "SHA3256",
		hashes: []string{
			"d60fcf6585da4e17224f58858970f0ed5ab042c3916b76b0b828e62eaf636cbd",
		},
		want: "SHA3-256",
	},
	{
		name: "SHA3384",
		hashes: []string{
			"983ba28532cc6320d04f20fa485bcedb38bddb666eca5f1e5aa279ff1c6244fe5f83cf4bbf05b95ff378dd2353617221",
		},
		want: "SHA3-384",
	},
	{
		name: "SHA3512",
		hashes: []string{
			"7c2dc1d743735d4e069f3bda85b1b7e9172033dfdd8cd599ca094ef8570f3930c3f2c0b7afc8d6152ce4eaad6057a2ff22e71934b3a3dd0fb55a7fc84a53144e",
		},
		want: "SHA3-512",
	},
	{
		name: "SIPDigestAuthenticationMD5",
		hashes: []string{
			"$sip$*192.168.100.100*192.168.100.121*username*asterisk*REGISTER*sip*192.168.100.121**2b01df0b****MD5*ad0520061ca07c120d7e8ce696a6df2d",
		},
		want: "SIP digest authentication (MD5)",
	},
	{
		name: "SMFSimpleMachinesForum>v11",
		hashes: []string{
			"ecf076ce9d6ed3624a9332112b1cd67b236fdd11:17782686",
		},
		want: "SMF (Simple Machines Forum) > v1.1",
	},
	{
		name: "SNMPv3HMACMD596",
		hashes: []string{
			"$SNMPv3$1$45889431$30818f0201033011020409242fc0020300ffe304010102010304383036041180001f88808106d566db57fd600000000002011002020118040a6d61747269785f4d4435040c0000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a226020411f319300201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$1b37c3ea872731f922959e90",
		},
		want: "SNMPv3 HMAC-MD5-96",
	},
	{
		name: "SNMPv3HMACMD596HMACSHA196",
		hashes: []string{
			"$SNMPv3$0$45889431$30818f0201033011020409242fc0020300ffe304010102010304383036041180001f88808106d566db57fd600000000002011002020118040a6d61747269785f4d4435040c0000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a226020411f319300201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$1b37c3ea872731f922959e90",
		},
		want: "SNMPv3 HMAC-MD5-96/HMAC-SHA1-96",
	},
	{
		name: "SNMPv3HMACSHA196",
		hashes: []string{
			"$SNMPv3$2$45889431$30818f02010330110204371780f3020300ffe304010102010304383036041180001f88808106d566db57fd600000000002011002020118040a6d61747269785f534841040c0000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a2260204073557d50201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$81f14f1930589f26f6755f6b",
		},
		want: "SNMPv3 HMAC-SHA1-96",
	},
	{
		name: "SNMPv3HMACSHA224128",
		hashes: []string{
			"$SNMPv3$3$45889431$308197020103301102047aa1a79e020300ffe30401010201030440303e041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d3232340410000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a2260204272f76620201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$2f7a3891dd2e27d3f567e4d6d0257962",
		},
		want: "SNMPv3 HMAC-SHA224-128",
	},
	{
		name: "SNMPv3HMACSHA256192",
		hashes: []string{
			"$SNMPv3$4$45889431$30819f020103301102047fc51818020300ffe304010102010304483046041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d32353604180000000000000000000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a22602040efec2600201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$36d655bfeb59e933845db47d719b68ac7bc59ec087eb89a0",
		},
		want: "SNMPv3 HMAC-SHA256-192",
	},
	{
		name: "SNMPv3HMACSHA384256",
		hashes: []string{
			"$SNMPv3$5$45889431$3081a70201033011020455c0c85c020300ffe30401010201030450304e041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d333834042000000000000000000000000000000000000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a226020411b3c3590201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd60$89424907553231aaa27055f4b3b0a97c626ed4cdc4b660d903765b607af792a5",
		},
		want: "SNMPv3 HMAC-SHA384-256",
	},
	{
		name: "SNMPv3HMACSHA512384",
		hashes: []string{
			"$SNMPv3$6$45889431$3081b702010330110204367c80d4020300ffe30401010201030460305e041180001f88808106d566db57fd600000000002011002020118040e6d61747269785f5348412d35313204300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000400303d041180001f88808106d566db57fd60000000000400a22602046ea3546f0201000201003018301606082b06010201010200060a2b06010401bf0803020a$80001f88808106d566db57fd6000000000$9e4681768d5dee9e2d0ca7380dfa19f0a0f805c550142b889af548f5506c2c3587df980707600b58d97ed1beaa9feaf9",
		},
		want: "SNMPv3 HMAC-SHA512-384",
	},
	{
		name: "SQLCipher",
		hashes: []string{
			"SQLCIPHER*1*64000*25548249195677404156261816261456*85b5e156e1cf1e0be5e9f4217186817b*33435c230bbc7989bbd027630e3f47cd",
		},
		want: "SQLCipher",
	},
	{
		name: "SSHA256Base64LDAPSSHA256",
		hashes: []string{
			"{SSHA256}OZiz0cnQ5hgyel3Emh7NCbhBRCQ+HVBwYplQunHYnER7TLuV",
		},
		want: "SSHA-256(Base64), LDAP {SSHA256}",
	},
	{
		name: "SSHA512Base64LDAPSSHA512",
		hashes: []string{
			"{SSHA512}ALtwKGBdRgD+U0fPAy31C28RyKYx7+a8kmfksccsOeLknLHv2DBXYI7TDnTolQMBuPkWDISgZr2cHfnNPFjGZTEyNDU4OTkw",
		},
		want: "SSHA-512(Base64), LDAP {SSHA512}",
	},
	{
		name: "Salsa10",
		hashes: []string{
			"105fe39a3683df2cd905fcccf41c8f5407262df7819072ac2f1c57653eb6c57fd203e4a7f1b4f1226321c146a6d934710bc3d0448a2ca554d44748fbdd3b6de2",
		},
		want: "Salsa10",
	},
	{
		name: "Salsa20",
		hashes: []string{
			"e819bc2b7915f5bf60adca7915a3540875486c0448a149ed7705da1186d1d73173b7e01b2050c540a6ee8a891a322207d8d86f9c556bd20827adf2b2808ffdb2",
		},
		want: "Salsa20",
	},
	{
		name: "SamsungAndroidPasswordPIN",
		hashes: []string{
			"0223b799d526b596fe4ba5628b9e65068227e68e:f6d45822728ddb2c",
		},
		want: "Samsung Android Password/PIN",
	},
	{
		name: "SecureZIPAES128",
		hashes: []string{
			"$zip3$*0*1*128*0*b4630625c92b6e7848f6fd86*df2f62611b3d02d2c7e05a48dad57c7d93b0bac1362261ab533807afb69db856676aa6e350320130b5cbf27c55a48c0f75739654ac312f1cf5c37149557fc88a92c7e3dde8d23edd2b839036e88092a708b7e818bf1b6de92f0efb5cce184cceb11db6b3ca0527d0bdf1f1137ee6660d9890928cd80542ac1f439515519147c14d965b5ba107c6227f971e3e115170bf*0*0*0*file.txt",
		},
		want: "SecureZIP AES-128",
	},
	{
		name: "SecureZIPAES192",
		hashes: []string{
			"$zip3$*0*1*192*0*53ff2de8c280778e1e0ab997*603eb37dbab9ea109e2c405e37d8cae1ec89e1e0d0b9ce5bf55d1b571c343b6a3df35fe381c30249cb0738a9b956ba8e52dfc5552894296300446a771032776c811ff8a71d9bb3c4d6c37016c027e41fea2d157d5b0ce17804b1d7c1606b7c1121d37851bd705e001f2cd755bbf305966d129a17c1d48ff8e87cfa41f479090cd456527db7d1d43f9020ad8e73f851a5*0*0*0*file.txt",
		},
		want: "SecureZIP AES-192",
	},
	{
		name: "SecureZIPAES256",
		hashes: []string{
			"$zip3$*0*1*256*0*39bff47df6152a0214d7a967*65ff418ffb3b1198cccdef0327c03750f328d6dd5287e00e4c467f33b92a6ef40a74bb11b5afad61a6c3c9b279d8bd7961e96af7b470c36fc186fd3cfe059107021c9dea0cf206692f727eeca71f18f5b0b6ee1f702b648bba01aa21c7b7f3f0f7d547838aad46868155a04214f22feef7b31d7a15e1abe6dba5e569c62ee640783bb4a54054c2c69e93ece9f1a2af9d*0*0*0*file.txt",
		},
		want: "SecureZIP AES-256",
	},
	{
		name: "SiemensS7",
		hashes: []string{
			"$siemens-s7$$1$5644714b707234646830473673445631744d4a68$0fea2b913571d06e60b28e6a61fd70f52e456fa1",
		},
		want: "Siemens-S7",
	},
	{
		name: "SipHash",
		hashes: []string{
			"ad61d78c06037cd9:2:4:81533218127174468417660201434054",
		},
		want: "SipHash",
	},
	{
		name: "Skein1024",
		hashes: []string{
			"62b6c4521a646a099850699ea262d3f5a73290959fd34734b4015097eb7b2700e964236f0b213193f0a15b82eb08a0bf330d60421fc81e9a9383df72172ce9787fde19ea0813a566cb62c55d042d0d9a0f86d87ae40de85a9b247225968aea29ba878cf0c30c44a181f3ef8e47975da80ca21f244b81504ebfb446924dcd7061",
		},
		want: "Skein-1024",
	},
	{
		name: "Skein1024384",
		hashes: []string{
			"9e5c86653868f1d2a4a208eae807a031371dcaac17ce3ef74845a0602b9ac16ee52e95afc58c993161ea3223c63a486b",
		},
		want: "Skein-1024(384)",
	},
	{
		name: "Skein1024512",
		hashes: []string{
			"b132215e3fd6aebcdff044cf3824eee6de27de9e994dac41a65d28279c08cbd7e69b21bef892475265d7958e2e6ef59012e9a8ec4de38e774b17bbb9fce2f94a",
		},
		want: "Skein-1024(512)",
	},
	{
		name: "Skein256",
		hashes: []string{
			"31947ae23c6b0022d6e69280675dd57c385441887c422892c0ba805298408c1d",
		},
		want: "Skein-256",
	},
	{
		name: "Skein256128",
		hashes: []string{
			"8a33fdcc414954540140569b9ca04969",
		},
		want: "Skein-256(128)",
	},
	{
		name: "Skein256160",
		hashes: []string{
			"4be29115203aaf1705dd2e645077b7380d2bf17f",
		},
		want: "Skein-256(160)",
	},
	{
		name: "Skein256224",
		hashes: []string{
			"9ac0082bb1b2f3004fffa45300a74f2855f2308426fd5e9f0e4c39ec",
		},
		want: "Skein-256(224)",
	},
	{
		name: "Skein512",
		hashes: []string{
			"6a7f3568a6dfc8d74f478d787e10617787ea35557a909152c13cdc9ef3e8cce28560269748e0f2d58ea76cad67f70583e821d73220982fa5c9c68809edd43568",
		},
		want: "Skein-512",
	},
	{
		name: "Skein-512128",
		hashes: []string{
			"e88eba6045f6a00672c398e2e2ce4959",
		},
		want: "Skein-512(128)",
	},
	{
		name: "Skein-512160",
		hashes: []string{
			"4721295b14d704a452a56e948e52ca4ea296ca75",
		},
		want: "Skein-512(160)",
	},
	{
		name: "Skein-512224",
		hashes: []string{
			"bf3e58d8cb9a2dd31215fb3b825896ae8d22514747cda7796f3e8c25",
		},
		want: "Skein-512(224)",
	},
	{
		name: "Skein-512256",
		hashes: []string{
			"2fee3ce07ffef3d2f78a6f7b38a8f294b70e902f9d0f8f514e34d48d93b55f31",
		},
		want: "Skein-512(256)",
	},
	{
		name: "Skein-512384",
		hashes: []string{
			"15f969b2d608f69b5e0873b0d10f195c57db84c45f35b535585a1452a9919888711b9de7717f9e47786319a102a74554",
		},
		want: "Skein-512(384)",
	},
	{
		name: "Skip32PT$SaltKey$Pass",
		hashes: []string{
			"c9350366:44630464",
		},
		want: "Skip32 (PT = $salt, key = $pass)",
	},
	{
		name: "Skype",
		hashes: []string{
			"3af0389f093b181ae26452015f4ae728:user",
		},
		want: "Skype",
	},
	{
		name: "Snefru128",
		hashes: []string{
			"1dc9a09e23a3f8184b8e40f3ad872842",
		},
		want: "Snefru-128",
	},
	{
		name: "Snefru256",
		hashes: []string{
			"cce3b171a7ede4c0a2d1a2db832035547226fade66980c7a62bd86c3ec1e82d1",
		},
		want: "Snefru-256",
	},
	{
		name: "SolarWindsOrion",
		hashes: []string{
			"$solarwinds$0$admin$fj4EBQewCQUZ7IYHl0qL8uj9kQSBb3m7N4u0crkKK0Uj9rbbAnSrBZMXO7oWx9KqL3sCzwncvPZ9hyDV9QCFTg==",
		},
		want: "SolarWinds Orion",
	},
	{
		name: "SolarWindsOrionV2",
		hashes: []string{
			"$solarwinds$1$3pHkk55NTYpAeV3EJjcAww==$N4Ii2PxXX/bTZZwslQLIKrp0wvfZ5aN9hpyiR896ozJMJTPO1Q7BK1Eht8Vhl4kXq/42Vn2zp3qYeAkRuqsuEw==",
		},
		want: "SolarWinds Orion v2",
	},
	{
		name: "SolarWindsServU",
		hashes: []string{
			"e983672a03adcc9767b24584338eb378",
		},
		want: "SolarWinds Serv-U",
	},
	{
		name: "StargazerStellarWalletXLM",
		hashes: []string{
			"$stellar$YAlIJziURRcBEWUwRSRDWA==$EutMmmcV5Hbf3p1I$rfSAF349RvGKG4R4Z2VCrH9WjNEKjbJa9hpOja9Yn8MwXruuFEMtw47HPn9CYj+JJ5Rb4Z87Wejj1c4fqpbMZHFOnqtQsVAr",
		},
		want: "Stargazer Stellar Wallet XLM",
	},
	{
		name: "Stuffit5",
		hashes: []string{
			"66a75cb059",
		},
		want: "Stuffit5",
	},
	{
		name: "SunMD5Crypt",
		hashes: []string{
			"$md5$rounds=904$iPPKEBnEkp3JV8uX$0L6m7rOFTVFn.SGqo2M9W1",
		},
		want: "Sun MD5 Crypt",
	},
	{
		name: "SybaseASE",
		hashes: []string{
			"0xc00778168388631428230545ed2c976790af96768afa0806fe6c0da3b28f3e132137eac56f9bad027ea2",
		},
		want: "Sybase ASE",
	},
	{
		name: "TACACS+",
		hashes: []string{
			"$tacacs-plus$0$5fde8e68$4e13e8fb33df$c006",
		},
		want: "TACACS+",
	},
	{
		name: "TOTPHMACSHA1",
		hashes: []string{
			"597056:3600",
		},
		want: "TOTP (HMAC-SHA1)",
	},
	{
		name: "TelegramDesktop<v2114PBKDF2HMACSHA1",
		hashes: []string{
			"$telegram$1*4000*913a7e42143b4eed0fb532dacfa04e3a0eae036ae66dd02de76323046c575531*cde5f7a3bda3812b4a3cd4df1269c6be18ca7536981522c251cab531c274776804634cdca5313dc8beb9895f903a40d874cd50dbb82e5e4d8f264820f3f2e2111a5831e1a2f16b1a75b2264c4b4485dfe0f789071130160af205f9f96aef378ee05602de2562f8c3b136a75ea01f54f4598af93f9e7f98eb66a5fd3dabaa864708fe0e84b59b77686974060f1533e3acc5367bc493915b5614603cf5601cfa0a6b8eae4c4bd24948176dd7ff470bc0863f35fdfce31a667c70e37743f662bc9c5ec86baff3ebb6bf7de96bcdfaca18baf9617a979424f792ef6e65e346ea2cbc1d53377f47c3fc681d7eda8169e6e20cd6a22dd94bf24933b8ffc4878216fa9edc7c72a073446a14b63e12b223f840217a7eac51b6afcc15bfa12afd3e85d3bd",
		},
		want: "Telegram Desktop < v2.1.14 (PBKDF2-HMAC-SHA1)",
	},
	{
		name: "TelegramDesktop>=v2114PBKDF2HMACSHA512",
		hashes: []string{
			"$telegram$2*100000*77461dcb457ce9539f8e4235d33bd12455b4a38446e63b52ecdf2e7b65af4476*f705dda3247df6d690dfc7f44d8c666979737cae9505d961130071bcc18eeadaef0320ac6985e4a116834c0761e55314464aae56dadb8f80ab8886c16f72f8b95adca08b56a60c4303d84210f75cfd78a3e1a197c84a747988ce2e1b247397b61041823bdb33932714ba16ca7279e6c36b75d3f994479a469b50a7b2c7299a4d7aadb775fb030d3bb55ca77b7ce8ac2f5cf5eb7bdbcc10821b8953a4734b448060246e5bb93f130d6d3f2e28b9e04f2a064820be562274c040cd849f1473d45141559fc45da4c54abeaf5ca40d2d57f8f8e33bdb232c7279872f758b3fb452713b5d91c855383f7cec8376649a53b83951cf8edd519a99e91b8a6cb90153088e35d9fed332c7253771740f49f9dc40c7da50352656395bbfeae63e10f754d24a",
		},
		want: "Telegram Desktop >= v2.1.14 (PBKDF2-HMAC-SHA512)",
	},
	{
		name: "TelegramMobileAppPasscodeSHA256",
		hashes: []string{
			"$telegram$0*518c001aeb3b4ae96c6173be4cebe60a85f67b1e087b045935849e2f815b5e41*25184098058621950709328221838128",
		},
		want: "Telegram Mobile App Passcode (SHA256)",
	},
	{
		name: "Tiger128",
		hashes: []string{
			"9123dc36b0b67ce3e79d0142820f3dc7",
		},
		want: "Tiger-128",
	},
	{
		name: "Tiger160",
		hashes: []string{
			"9123dc36b0b67ce3e79d0142820f3dc7b3945967",
		},
		want: "Tiger-160",
	},
	{
		name: "Tiger192",
		hashes: []string{
			"9123dc36b0b67ce3e79d0142820f3dc7b3945967b4e7196c",
		},
		want: "Tiger-192",
	},
	{
		name: "Tripcode",
		hashes: []string{
			"pfaRCwDe0U",
		},
		want: "Tripcode",
	},
	{
		name: "VMwareVMXPBKDF2HMACSHA1AES256CBC",
		hashes: []string{
			"$vmx$0$10000$264bbab02fdf7c1a793651120bec3723$cbb368564d8dfb99f509d4922f4693413f3816af713f0e76bc2409ff9336935d",
		},
		want: "VMware VMX (PBKDF2-HMAC-SHA1 + AES-256-CBC)",
	},
	{
		name: "VNC",
		hashes: []string{
			"$vnc$*84076F040550EEA9341967633B5F3855*DD96D21781A70DA49443279975404DD0",
		},
		want: "VNC",
	},
	{
		name: "Ventrilo",
		hashes: []string{
			"1621a36cbd1ce49c5810c9b69468cc9c8eb16089cd7ed3493143f92c2d8064fe",
		},
		want: "Ventrilo",
	},
	{
		name: "VirtualBoxPBKDF2HMACSHA256AES128XTS",
		hashes: []string{
			"$vbox$0$260000$fcc37189521686699a43e49514b91f159306be108b98895666583cd15c3e206b$8$288c3957db47e7c3dff2f7932121eb3395d21ab76b9cf3de2dc660310a25e7ad$20000$8847cd90f8acef74bae41155392908780eebb1d16452aa09b2f7b6cd7d8a4096$9f4d615b484f95c73944a98f392a3ce04f93403e8bb6257e6b6c854273d3a08a",
		},
		want: "VirtualBox (PBKDF2-HMAC-SHA256 & AES-128-XTS)",
	},
	{
		name: "VirtualBoxPBKDF2HMACSHA256AES256XTS",
		hashes: []string{
			"$vbox$0$160000$54aff69fca91c20b3b15618c6732c4a2f953dd88690cd4cc731569b6b80b5572$16$cfb003087e0c618afa9ad7e44adcd97517f039e0424dedb46db8affbb73cd064019abae19ee5e4f5b05b626e6bc5d7da65c61a5f94d7bcac521c388276e5358b$20000$2e5729055136168eea79cb3f1765450a35ab7540125f2ca2a46924a99fd0524d$b28d1db1cabe99ca989a405c33a27beeb9c0683b8b4b54b0e0d85f712f64d89c",
		},
		want: "VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)",
	},
	{
		name: "WBB3WoltlabBurningBoard",
		hashes: []string{
			"8084df19a6dc81e2597d051c3d8b400787e2d5a9:6755045315424852185115352765375338838643",
		},
		want: "WBB3 (Woltlab Burning Board)",
	},
	{
		name: "WBB4WoltlabBurningBoard",
		hashes: []string{
			"$2a$08$VPzNKPAY60FsAbnq.c.h5.XTCZtC1z.j3hnlDFGImN9FcpfR1QnLq",
		},
		want: "WBB4 (Woltlab Burning Board)",
	},
	{
		name: "WPAPBKDF2PMKIDEAPOL",
		hashes: []string{
			"WPA*01*4d4fe7aac3a2cecab195321ceb99a7d0*fc690c158264*f4747f87f9f4*686173686361742d6573736964***",
		},
		want: "WPA-PBKDF2-PMKID+EAPOL",
	},
	{
		name: "WPAPMKPMKIDEAPOL",
		hashes: []string{
			"WPA*01*5ce7ebe97a1bbfeb2822ae627b726d5b*27462da350ac*accd10fb464e*686173686361742d6573736964***",
		},
		want: "WPA-PMK-PMKID+EAPOL",
	},
	{
		name: "WPAPMKIDPBKDF2",
		hashes: []string{
			"2582a8281bf9d4308d6f5731d0e61c61*4604ba734d4e*89acf0e761f4*ed487162465a774bfba60eb603a39f3a",
		},
		want: "WPA-PMKID-PBKDF2",
	},
	{
		name: "WPAPMKIDPMK",
		hashes: []string{
			"2582a8281bf9d4308d6f5731d0e61c61*4604ba734d4e*89acf0e761f4",
		},
		want: "WPA-PMKID-PMK",
	},
	{
		name: "Web2pyPBKDF2SHA512",
		hashes: []string{
			"pbkdf2(1000,20,sha512)$744943$c5f8cdef76e3327c908d8d96d4abdb3d8caba14c",
		},
		want: "Web2py pbkdf2-sha512",
	},
	{
		name: "WebEditionCMS",
		hashes: []string{
			"fa01af9f0de5f377ae8befb03865178e:5678",
		},
		want: "WebEdition CMS",
	},
	{
		name: "Whirlpool",
		hashes: []string{
			"7ca8eaaaa15eaa4c038b4c47b9313e92da827c06940e69947f85bc0fbef3eb8fd254da220ad9e208b6b28f6bb9be31dd760f1fdb26112d83f87d96b416a4d258",
		},
		want: "Whirlpool",
	},
	{
		name: "WinZip",
		hashes: []string{
			"$zip2$*0*3*0*e3222d3b65b5a2785b192d31e39ff9de*1320*e*19648c3e063c82a9ad3ef08ed833*3135c79ecb86cd6f48fc*$/zip2$",
		},
		want: "WinZip",
	},
	{
		name: "WindowsHelloPINPassword",
		hashes: []string{
			"$WINHELLO$*SHA512*10000*00761655*3b3d3197efb2839a6072e922cc03be910be55d1e60389689c05b520d2d57c06258dc5a48798ba65424004cbe2e003d0509036f3394bcae108eb6b77c7eb306d7*c0772a3aca949db60f274f315b3a5f63fea552fc0d1f2032db5293ca9690735217d918d4cf697aa45b2fe598168804040e18fe00758be94aac971985ea7a5521*bff47e398df761733b5aeda7035cdf289547db3afb94b70cbad2aaea21a5cd58*8a4d5b88832e10bad57303324e6c9021733733df4acbf91366f51cebdc755e00fe1d01b3202469ee6ad5e667975b4f50e3110b00ef60414cd2cf96cc47df532e36b997727ffec2924d979d3fb6e677cb5827f4313131a46be8712926c42158339b55183e2fd7f2f0761980b1413897825c3759c566ff8a438189a6c8fb2d630dc33c6330de45c784d11957c686b40b6fe31fd8f2b1b664f542392326af5d334fdf92155343335e1b964955ac0b0e6f7254a599f0f0dc99becc2216515ba9e9472a54e60a14507fc353ebc47b9f0a8249a2a1bfa5d2cf526bd15ee68bd52e944ece9de6bbda913bc5083e26229673340fcc5285df0d38cbc7bb14584ced2fe9e9b3c283fa3c5ad4dd2034b7a67c8e7a1632fae8979a0abdd19be91c6bc371966121e04d433923e44df0b60c156bd90bc61c9fed01a7a76353f79dd4da3e07e12810ec3765128ec44b44b0789d6aa9e9702211a22ab8055ea32e9513fb1bd9d24ca04b33282632f63ab1b213e9644f97bc31dc4d2e7050c1fa23c0000facbf7c76fd7be4b112586f73f0c27abcf7cbe8c9d9fb83af70f60c490936fef84ed5301f73917b4e4170674a5d5e4bfbebdfeda9584221a0f190545efea7245dd2517ade393bedc255c4e016d9919e6e3f3711bca677fc099bf4e1730a752ea2a90a20ff3d09c909771849d3b009ba8d95d2b84fff889e38b079f1325aa42daa067a52abb5c064de3a5040e4a64e76b397b5c9ee6d045f3b5150cf428a92c141735908bb278077d52beefdc87efa156b8ebda071cb425fad0372a8a7cb6eb29926e8f6411ff1b818750c5b6888302fee9b1591b1c23db131538db2aa3de61dcd76fb7067be7ab71ee372bac18be0f446c974e92e79e27e7e3b2aa5ffc3f5f923f2df8ac2edcbb9392d1ac35e4cd52037d9dceedec6391e713e78770307bfde6a31b4e115904d285ac35db055ae8253b9968b7ed7b948da5f*785435725a573571565662727670754100",
		},
		want: "Windows Hello PIN/Password",
	},
	{
		name: "WindowsPhone8+PINPassword",
		hashes: []string{
			"95fc4680bcd2a5f25de3c580cbebadbbf256c1f0ff2e9329c58e36f8b914c11f:4471347156480581513210137061422464818088437334031753080747625028271635402815635172140161077854162657165115624364524648202480341513407048222056541500234214433548175101668212658151115765112202168288664210443352443335235337677853484573107775345675846323265745",
		},
		want: "Windows Phone 8+ PIN/password",
	},
	{
		name: "XMPPSCRAMPBKDF2SHA1",
		hashes: []string{
			"$xmpp-scram$0$4096$32$bbc1467455fd9886f6c5d15200601735e159e807d53a1c80853b570321aaeceb$8301c6e0245e4a986ed64a9b1803afb1854d9712",
		},
		want: "XMPP SCRAM PBKDF2-SHA1",
	},
	{
		name: "XOR32",
		hashes: []string{
			"00000004",
		},
		want: "XOR-32",
	},
	{
		name: "ZipMonster",
		hashes: []string{
			"dfcbda4dad0d7600e2096ce4bf09c117",
		},
		want: "ZipMonster",
	},
	{
		name: "bcrypt",
		hashes: []string{
			"$2a$12$djEXehnXL2xWQRq5w.LbFOaNDNlebYzDbAfwWwzY7oKrbdMe4OYwO",
		},
		want: "bcrypt",
	},
	{
		name: "bcrypt$2$BlowfishUnix",
		hashes: []string{
			"$2a$05$LhayLxezLhK1LhWvKxCyLOj0j1u.Kj0jZ0pEmm134uzrQlFvQJLF6",
		},
		want: "bcrypt $2*$, Blowfish (Unix)",
	},
	{
		name: "bcryptSHA256",
		hashes: []string{
			"$bcrypt-sha256$2a,12$etprdT4l6EppsPWYBCjUP.$V0zQ4JShuLJLpQXWmc8zLa9XH7MzQwe",
		},
		want: "bcrypt(SHA-256)",
	},
	{
		name: "bcryptMD5$PassbcryptMD5",
		hashes: []string{
			"$2a$05$/VT2Xs2dMd8GJKfrXhjYP.DkTjOVrY12yDN7/6I8ZV0q/1lEohLru",
		},
		want: "bcrypt(md5($pass)) / bcryptmd5",
	},
	{
		name: "bcryptSHA1$PassbcryptSHA1",
		hashes: []string{
			"$2a$05$Uo385Fa0g86uUXHwZxB90.qMMdRFExaXePGka4WGFv.86I45AEjmO",
		},
		want: "bcrypt(sha1($pass)) / bcryptsha1",
	},
	{
		name: "descryptDESUnixTraditionalDES",
		hashes: []string{
			"48c/R8JAv757A",
		},
		want: "descrypt, DES (Unix), Traditional DES",
	},
	{
		name: "eCryptfs",
		hashes: []string{
			"$ecryptfs$0$1$7c95c46e82f364b3$60bba503f0a42d0c",
		},
		want: "eCryptfs",
	},
	{
		name: "hMailServer",
		hashes: []string{
			"8fe7ca27a17adc337cd892b1d959b4e487b8f0ef09e32214f44fb1b07e461c532e9ec3",
		},
		want: "hMailServer",
	},
	{
		name: "iPhonePasscodeUIDKeySystemKeybag",
		hashes: []string{
			"$uido$77889b1bca161ce876d976a102c7bf82$3090545724551425617156367874312887832777$50000$2d4c86b71c0c04129a47c6468e2437d1fecd88e232a7b15112d5364682dc391dbbbb921cf6e02664",
		},
		want: "iPhone passcode (UID key + System Keybag)",
	},
	{
		name: "iSCSICHAPAuthenticationMD5CHAP",
		hashes: []string{
			"afd09efdd6f8ca9f18ec77c5869788c3:01020304050607080910111213141516:01",
		},
		want: "iSCSI CHAP authentication, MD5(CHAP)",
	},
	{
		name: "iTunesBackup<100",
		hashes: []string{
			"$itunes_backup$*9*b8e3f3a970239b22ac199b622293fe4237b9d16e74bad2c3c3568cd1bd3c471615a6c4f867265642*10000*4542263740587424862267232255853830404566**",
		},
		want: "iTunes backup < 10.0",
	},
	{
		name: "iTunesBackup>=100",
		hashes: []string{
			"$itunes_backup$*10*8b715f516ff8e64442c478c2d9abb046fc6979ab079007d3dbcef3ddd84217f4c3db01362d88fa68*10000*2353363784073608264337337723324886300850*10000000*425b4bb4e200b5fd4c66979c9caca31716052063",
		},
		want: "iTunes backup >= 10.0",
	},
	{
		name: "macOSv104macOSv105macOSv106",
		hashes: []string{
			"1430823483d07626ef8be3fda2ff056d0dfd818dbfe47683",
		},
		want: "macOS v10.4, macOS v10.5, macOS v10.6",
	},
	{
		name: "macOSv107",
		hashes: []string{
			"648742485c9b0acd786a233b2330197223118111b481abfa0ab8b3e8ede5f014fc7c523991c007db6882680b09962d16fd9c45568260531bdb34804a5e31c22b4cfeb32d",
		},
		want: "macOS v10.7",
	},
	{
		name: "macOSv108+PBKDF2SHA512",
		hashes: []string{
			"$ml$35460$93a94bd24b5de64d79a5e49fa372827e739f4d7b6975c752c9a0ff1e5cf72e05$752351df64dd2ce9dc9c64a72ad91de6581a15c19176266b44d98919dfa81f0f96cbcb20a1ffb400718c20382030f637892f776627d34e021bad4f81b7de8222",
		},
		want: "macOS v10.8+ (PBKDF2-SHA512)",
	},
	{
		name: "md5$Salt$Pass",
		hashes: []string{
			"f0fda58630310a6dd91a7d8f0a4ceda2:4225637426",
		},
		want: "md5($salt.$pass)",
	},
	{
		name: "md5$Salt$Pass$Salt",
		hashes: []string{
			"2e45c4b99396c6cb2db8bda0d3df669f:1234",
		},
		want: "md5($salt.$pass.$salt)",
	},
	{
		name: "md5$Saltmd5$Pass",
		hashes: []string{
			"95248989ec91f6d0439dbde2bd0140be:1234",
		},
		want: "md5($salt.md5($pass))",
	},
	{
		name: "md5$Saltmd5$Pass$Salt",
		hashes: []string{
			"b4cb5c551a30f6c25d648560408df68a:1234",
		},
		want: "md5($salt.md5($pass.$salt))",
	},
	{
		name: "md5$Saltmd5$Salt$Pass",
		hashes: []string{
			"30d0cf4a5d7ed831084c5b8b0ba75b46:1234",
		},
		want: "md5($salt.md5($salt.$pass))",
	},
	{
		name: "md5$Saltsha1$Salt$Pass",
		hashes: []string{
			"799dc7d9aa4d3f404cc21a4936dbdcde:68617368636174",
		},
		want: "md5($salt.sha1($salt.$pass))",
	},
	{
		name: "md5$Saltutf16le$Pass",
		hashes: []string{
			"d63d0e21fdc05f618d55ef306c54af82:13288442151473",
		},
		want: "md5($salt.utf16le($pass))",
	},
	{
		name: "md5md5$Pass",
		hashes: []string{
			"a936af92b0ae20b1ff6c3347a72e5fbe",
		},
		want: "md5(md5($pass))",
	},
	{
		name: "md5md5$Passmd5$Salt",
		hashes: []string{
			"250920b3a5e31318806a032a4674df7e:1234",
		},
		want: "md5(md5($pass).md5($salt))",
	},
	{
		name: "md5md5md5$Pass",
		hashes: []string{
			"9882d0778518b095917eb589f6998441",
		},
		want: "md5(md5(md5($pass)))",
	},
	{
		name: "md5sha1$Pass",
		hashes: []string{
			"288496df99b33f8f75a7ce4837d1b480",
		},
		want: "md5(sha1($pass))",
	},
	{
		name: "md5sha1$Passmd5$Passsha1$Pass",
		hashes: []string{
			"100b3a4fc1dc8d60d9bf40688d8b740a",
		},
		want: "md5(sha1($pass).md5($pass).sha1($pass))",
	},
	{
		name: "md5sha1$Saltmd5$Pass",
		hashes: []string{
			"e69b7a7fe1bf2ad9ef116f79551ee919:baa038987e582431a6d",
		},
		want: "md5(sha1($salt).md5($pass))",
	},
	{
		name: "md5strtouppermd5$Pass",
		hashes: []string{
			"b8c385461bb9f9d733d3af832cf60b27",
		},
		want: "md5(strtoupper(md5($pass)))",
	},
	{
		name: "md5utf16le$Pass",
		hashes: []string{
			"2303b15bfa48c74a74758135a0df1201",
		},
		want: "md5(utf16le($pass))",
	},
	{
		name: "md5utf16le$Pass$Salt",
		hashes: []string{
			"b31d032cfdcf47a399990a71e43c5d2a:144816",
		},
		want: "md5(utf16le($pass).$salt)",
	},
	{
		name: "md5cryptMD5UnixCiscoIOS$1$MD5",
		hashes: []string{
			"$1$28772684$iEwNOgGugqO9.bIz5sk8k/",
		},
		want: "md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)",
	},
	{
		name: "nsldapSHA1Base64NetscapeLDAPSHA",
		hashes: []string{
			"{SHA}uJ6qx+YUFzQbcQtyd2gpTQ5qJ3s=",
		},
		want: "nsldap, SHA-1(Base64), Netscape LDAP SHA",
	},
	{
		name: "nsldapsSSHA1Base64NetscapeLDAPSSHA",
		hashes: []string{
			"{SSHA}AZKja92fbuuB9SpRlHqaoXxbTc43Mzc2MDM1Ng==",
		},
		want: "nsldaps, SSHA-1(Base64), Netscape LDAP SSHA",
	},
	{
		name: "osCommercextCommerce",
		hashes: []string{
			"374996a5e8a5e57fd97d893f7df79824:36",
		},
		want: "osCommerce, xt:Commerce",
	},
	{
		name: "phpassWordPressMD5JoomlaMD5",
		hashes: []string{
			"$P$984478476IagS59wHZvyQMArzfx58u.",
		},
		want: "phpass, WordPress (MD5), Joomla (MD5)",
	},
	{
		name: "phpassphpBB3MD5",
		hashes: []string{
			"$H$984478476IagS59wHZvyQMArzfx58u.",
		},
		want: "phpass, phpBB3 (MD5)",
	},
	{
		name: "scrypt",
		hashes: []string{
			"SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=",
		},
		want: "scrypt",
	},
	{
		name: "sha1$Pass$Salt",
		hashes: []string{
			"2fc5a684737ce1bf7b3b239df432416e0dd07357:2014",
		},
		want: "sha1($pass.$salt)",
	},
	{
		name: "sha1$Salt$Pass",
		hashes: []string{
			"cac35ec206d868b7d7cb0b55f31d9425b075082b:5363620024",
		},
		want: "sha1($salt.$pass)",
	},
	{
		name: "sha1$Salt$Pass$Salt",
		hashes: []string{
			"85087a691a55cbb41ae335d459a9121d54080b80:488387841",
		},
		want: "sha1($salt.$pass.$salt)",
	},
	{
		name: "sha1$Saltsha1$Pass",
		hashes: []string{
			"a0f835fdf57d36ebd8d0399cc44e6c2b86a1072b:511358214352751667201107073531735211566650747315",
		},
		want: "sha1($salt.sha1($pass))",
	},
	{
		name: "sha1$Saltsha1$Pass$Salt",
		hashes: []string{
			"94520b02c04e79e08a75a84c2a6e3ed4e3874fe8:ThisIsATestSalt",
		},
		want: "sha1($salt.sha1($pass.$salt))",
	},
	{
		name: "sha1$Saltutf16le$Pass",
		hashes: []string{
			"5db61e4cd8776c7969cfd62456da639a4c87683a:8763434884872",
		},
		want: "sha1($salt.utf16le($pass))",
	},
	{
		name: "sha1$Salt1$Pass$Salt2",
		hashes: []string{
			"630d2e918ab98e5fad9c61c0e4697654c4c16d73:18463812876898603420835420139870031762867:4449516425193605979760642927684590668549584534278112685644182848763890902699756869283142014018311837025441092624864168514500447147373198033271040848851687108629922695275682773136540885737874252666804716579965812709728589952868736177317883550827482248620334",
		},
		want: "sha1($salt1.$pass.$salt2)",
	},
	{
		name: "sha1CX",
		hashes: []string{
			"fd9149fb3ae37085dc6ed1314449f449fbf77aba:87740665218240877702",
		},
		want: "sha1(CX)",
	},
	{
		name: "sha1md5$Pass",
		hashes: []string{
			"92d85978d884eb1d99a51652b1139c8279fa8663",
		},
		want: "sha1(md5($pass))",
	},
	{
		name: "sha1md5$Pass$Salt",
		hashes: []string{
			"53c724b7f34f09787ed3f1b316215fc35c789504:hashcat1",
		},
		want: "sha1(md5($pass).$salt)",
	},
	{
		name: "sha1md5$Pass$Salt",
		hashes: []string{
			"aade80a61c6e3cd3cac614f47c1991e0a87dd028:6",
		},
		want: "sha1(md5($pass.$salt))",
	},
	{
		name: "sha1md5md5$Pass",
		hashes: []string{
			"888a2ffcb3854fba0321110c5d0d434ad1aa2880",
		},
		want: "sha1(md5(md5($pass)))",
	},
	{
		name: "sha1sha1$Pass",
		hashes: []string{
			"3db9184f5da4e463832b086211af8d2314919951",
		},
		want: "sha1(sha1($pass))",
	},
	{
		name: "sha1sha1$Pass$Salt",
		hashes: []string{
			"9138d472fce6fe50e2a32da4eec4ecdc8860f4d5:hashcat1",
		},
		want: "sha1(sha1($pass).$salt)",
	},
	{
		name: "sha1sha1$Salt$Pass$Salt",
		hashes: []string{
			"05ac0c544060af48f993f9c3cdf2fc03937ea35b:232725102020",
		},
		want: "sha1(sha1($salt.$pass.$salt))",
	},
	{
		name: "sha1utf16le$Pass",
		hashes: []string{
			"b9798556b741befdbddcbf640d1dd59d19b1e193",
		},
		want: "sha1(utf16le($pass))",
	},
	{
		name: "sha1utf16le$Pass$Salt",
		hashes: []string{
			"c57f6ac1b71f45a07dbd91a59fa47c23abcd87c2:631225",
		},
		want: "sha1(utf16le($pass).$salt)",
	},
	{
		name: "sha256$Pass$Salt",
		hashes: []string{
			"c73d08de890479518ed60cf670d17faa26a4a71f995c1dcc978165399401a6c4:53743528",
		},
		want: "sha256($pass.$salt)",
	},
	{
		name: "sha256$Salt$Pass",
		hashes: []string{
			"eb368a2dfd38b405f014118c7d9747fcc97f4f0ee75c05963cd9da6ee65ef498:560407001617",
		},
		want: "sha256($salt.$pass)",
	},
	{
		name: "sha256$Salt$Pass$Salt",
		hashes: []string{
			"755a8ce4e0cf0baee41d714aa35c9fca803106608f718f973eab006578285007:11265",
		},
		want: "sha256($salt.$pass.$salt)",
	},
	{
		name: "sha256$Saltsha256$Pass",
		hashes: []string{
			"bae9edada8358fcebcd811f7d362f46277fb9d488379869fba65d79701d48b8b:869dc2ed80187919",
		},
		want: "sha256($salt.sha256($pass))",
	},
	{
		name: "sha256$Saltutf16le$Pass",
		hashes: []string{
			"a4bd99e1e0aba51814e81388badb23ecc560312c4324b2018ea76393ea1caca9:12345678",
		},
		want: "sha256($salt.utf16le($pass))",
	},
	{
		name: "sha256md5$Pass",
		hashes: []string{
			"74ee1fae245edd6f27bf36efc3604942479fceefbadab5dc5c0b538c196eb0f1",
		},
		want: "sha256(md5($pass))",
	},
	{
		name: "sha256sha256$Pass$Salt",
		hashes: []string{
			"bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824:7218532375810603",
		},
		want: "sha256(sha256($pass).$salt)",
	},
	{
		name: "sha256sha256bin$Pass",
		hashes: []string{
			"0cc1b58a543f372327aa0281e97ab56e345267ee46feabf7709515debb7ec43c",
		},
		want: "sha256(sha256_bin($pass))",
	},
	{
		name: "sha256utf16le$Pass",
		hashes: []string{
			"9e9283e633f4a7a42d3abc93701155be8afe5660da24c8758e7d3533e2f2dc82",
		},
		want: "sha256(utf16le($pass))",
	},
	{
		name: "sha256utf16le$Pass$Salt",
		hashes: []string{
			"4cc8eb60476c33edac52b5a7548c2c50ef0f9e31ce656c6f4b213f901bc87421:890128",
		},
		want: "sha256(utf16le($pass).$salt)",
	},
	{
		name: "sha256crypt$5$SHA256Unix",
		hashes: []string{
			"$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD",
		},
		want: "sha256crypt $5$, SHA256 (Unix)",
	},
	{
		name: "sha384$Pass$Salt",
		hashes: []string{
			"ca1c843a7a336234baf9db2e10bc38824ce523402fbd7741286b1602bdf6cb869a45289bb9fb706bd404b9f3842ff729:2746460797049820734631508",
		},
		want: "sha384($pass.$salt)",
	},
	{
		name: "sha384$Salt$Pass",
		hashes: []string{
			"63f63d7f82d4a4cb6b9ff37a6bc7c5ec39faaf9c9078551f5cbf7960e76ded87b643d37ac53c45bc544325e7ff83a1f2",
		},
		want: "sha384($salt.$pass)",
	},
	{
		name: "sha384$Saltutf16le$Pass",
		hashes: []string{
			"316e93ea8e04de3e5a909c53d36923a31a16c1b9e89b44201d6082f87ca49c5bca53cad65f685207db3ea2ccc7ca40f8:700067651",
		},
		want: "sha384($salt.utf16le($pass))",
	},
	{
		name: "sha384utf16le$Pass",
		hashes: []string{
			"48e61d68e93027fae35d405ed16cd01b6f1ae66267833b4a7aa1759e45bab9bba652da2e4c07c155a3d8cf1d81f3a7e8",
		},
		want: "sha384(utf16le($pass))",
	},
	{
		name: "sha384utf16le$Pass$Salt",
		hashes: []string{
			"3516a589d2ed4071bf5e36f22e11212b3ad9050b9094b23067103d51e99dcb25c4dc397dba8034fed11a8184acfbb699:577730514588712",
		},
		want: "sha384(utf16le($pass).$salt)",
	},
	{
		name: "sha512$Pass$Salt",
		hashes: []string{
			"e5c3ede3e49fb86592fb03f471c35ba13e8d89b8ab65142c9a8fdafb635fa2223c24e5558fd9313e8995019dcbec1fb584146b7bb12685c7765fc8c0d51379fd",
		},
		want: "sha512($pass.$salt)",
	},
	{
		name: "sha512$Salt$Pass",
		hashes: []string{
			"976b451818634a1e2acba682da3fd6efa72adf8a7a08d7939550c244b237c72c7d42367544e826c0c83fe5c02f97c0373b6b1386cc794bf0d21d2df01bb9c08a:2613516180127",
		},
		want: "sha512($salt.$pass)",
	},
	{
		name: "sha512$Saltutf16le$Pass",
		hashes: []string{
			"bae3a3358b3459c761a3ed40d34022f0609a02d90a0d7274610b16147e58ece00cd849a0bd5cf6a92ee5eb5687075b4e754324dfa70deca6993a85b2ca865bc8",
		},
		want: "sha512($salt.utf16le($pass))",
	},
	{
		name: "sha512utf16le$Pass",
		hashes: []string{
			"79bba09eb9354412d0f2c037c22a777b8bf549ab12d49b77d5b25faa839e4378d8f6fa11aceb6d9413977ae5ad5d011568bad2de4f998d75fd4ce916eda83697",
		},
		want: "sha512(utf16le($pass))",
	},
	{
		name: "sha512utf16le$Pass$Salt",
		hashes: []string{
			"13070359002b6fbb3d28e50fba55efcf3d7cc115fe6e3f6c98bf0e3210f1c6923427a1e1a3b214c1de92c467683f6466727ba3a51684022be5cc2ffcb78457d2",
		},
		want: "sha512(utf16le($pass).$salt)",
	},
	{
		name: "sha512crypt$6$SHA512Unix",
		hashes: []string{
			"$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/",
		},
		want: "sha512crypt $6$, SHA512 (Unix)",
	},
	{
		name: "vBulletin<v385",
		hashes: []string{
			"16780ba78d2d5f02f3202901c1b6d975:568",
		},
		want: "vBulletin < v3.8.5",
	},
	{
		name: "vBulletin>=v385",
		hashes: []string{
			"bf366348c53ddcfbd16e63edfdd1eee6:181264250056774603641874043270",
		},
		want: "vBulletin >= v3.8.5",
	},
	{
		name: "DahuaNVRDVRHVRmd5$Salt1strtouppermd5$Salt2$Pass",
		hashes: []string{
			"0e1484eb061b8e9cfd81868bba1dc4a0:229381927:182719643",
		},
		want: "Dahua NVR/DVR/HVR (md5($salt1.strtoupper(md5($salt2.$pass))))",
	},
	{
		name: "md5sha1$Pass$Salt",
		hashes: []string{
			"bc8319c0220bff8a0d7f5d703114a725:34659348756345251",
		},
		want: "md5(sha1($pass).$salt)",
	},
	{
		name: "HMACRIPEMD160Key=$Pass",
		hashes: []string{
			"4f5edca01734e03dd7e735362625a76e6bcb61b2:52355614946067",
		},
		want: "HMAC-RIPEMD160 (key = $pass)",
	},
	{
		name: "HMACRIPEMD160Key=$Salt",
		hashes: []string{
			"34d8e55a2ae1e9549a291326ce2f0a8dcdc75c5c:08523202563542341",
		},
		want: "HMAC-RIPEMD160 (key = $salt)",
	},
	{
		name: "DPAPIMasterkeyFilev2Context3",
		hashes: []string{
			"$DPAPImk$2*3*S-15-21-464497560-472124119-475628788-1088*aes256*sha512*13450*685165fdb6d0627a15100215ec331ed8*288*7e1ea6f7ec3c2111f2a3903c73aefe66e524d8b241dc1482d0bd07cc1f3ccdadd8cebd4263b3b7c2496da48f40d2eb4890513e6624aeefbe6bbc6ea73f2f71fecf9cc5fef3891a2e697a4415ba7a069642069c142335d53cc750d42a4f4d2b0592956b4a0e57a5d5b1bfd27f0a8eac9d0d5fc5c5e5e23af18ce1a8eff442ed335e5db3bad6e89146f71aa9351e132fd9",
		},
		want: "DPAPI masterkey file v2 (context 3)",
	},
	{
		name: "BlockchainMyWalletSecondPasswordSHA256",
		hashes: []string{
			"YnM6WYERjJfhxwepT7zV6odWoEUz1X4esYQb4bQ3KZ7bbZAyOTc1MDM3OTc1NjMyODA0ECcAAD3vFoc=",
		},
		want: "Blockchain, My Wallet, Second Password (SHA256)",
	},
	{
		name: "sha256$Saltsha256bin$Pass",
		hashes: []string{
			"5934ea4d670c13a71155faba42056b2525f71bdc9215d31108990c11bf3d98e3:9269771356270099311432765354522635185291064175409115041569",
		},
		want: "sha256($salt.sha256_bin($pass))",
	},
	{
		name: "UmbracoHMACSHA1",
		hashes: []string{
			"8uigXlGMNI7BzwLCJlDbcKR2FP4=",
		},
		want: "Umbraco HMAC-SHA1",
	},
	{
		name: "MetaMaskWalletShortHashPlaintextCheck",
		hashes: []string{
			"$metamask-short$jfGI3TXguhb8GPnKSXFrMzRk2NCEc131Gt5G3kZr5+s=$h+BoIf2CQ5BEjaIOShFE7g==$R95fzGt4UQ0uwrcrVYnIi4UcSlWn9wlmer+//526ZDwYAp50K82F1u1oacYcdjjhuEvbZnWk/uBG00UkgLLlOw==",
		},
		want: "MetaMask Wallet (short hash, plaintext check)",
	},
	{
		name: "ExodusDesktopWalletScrypt",
		hashes: []string{
			"EXODUS:16384:8:1:IYkXZgFETRmFp4wQXyP8XMe3LtuOw8wMdLcBVQ+9YWE=:lq0W9ekN5sC0O7Xw:UD4a6mUUhkTbQtGWitXHZUg0pQ4RHI6W/KUyYE95m3k=:ZuNQckXOtr4r21x+DT1zpQ==",
		},
		want: "Exodus Desktop Wallet (scrypt)",
	},
	{
		name: "Teamspeak3ChannelHash",
		hashes: []string{
			"$teamspeak$3$E0aV0IQ29EDyxRfkFoQflUGJ6zo=$mRgDUkNpd0IwUEcTJQBmE0NHYwdDEhFzQ0VgMRcFJUIRYnaHBwNXRZJwk2ZUaURzdXkVYiUROERmI0hYYGFYCDiIJCeIU3N5EhRVcZFnSIRCJlkUFkY4YFMDcheYeTl4RYZEdpKGJYhxAIQJEYGYEA==",
		},
		want: "Teamspeak 3 (channel hash)",
	},
	{
		name: "bcryptsha512$Passbcryptsha512",
		hashes: []string{
			"$2a$12$KhivLhCuLhSyMBOxLxCyLu78x4z2X/EJdZNfS3Gy36fvRt56P2jbS",
		},
		want: "bcrypt(sha512($pass)) / bcryptsha512",
	},
	{
		name: "BitcoinWIFPrivateKeyP2PKHCompressed",
		hashes: []string{
			"1Jv6EonXm9x4Dw4QjEPAhGfmzFxTL7b3Zj",
		},
		want: "Bitcoin WIF private key (P2PKH), compressed",
	},
	{
		name: "BitcoinWIFPrivateKeyP2PKHUncompressed",
		hashes: []string{
			"1L9nr4GX4Zmd7gDL1UT75QPUqxSgNTvdHb",
		},
		want: "Bitcoin WIF private key (P2PKH), uncompressed",
	},
	{
		name: "BitcoinWIFPrivateKeyP2WPKHBech32Compressed",
		hashes: []string{
			"bc1qxd76a5zamfyw0g2d2rxkdh0zt9m0uzmxmwjf0q",
		},
		want: "Bitcoin WIF private key (P2WPKH, Bech32), compressed",
	},
	{
		name: "BitcoinWIFPrivateKeyP2WPKHBech32Uncompressed",
		hashes: []string{
			"bc1qv8e65p73gmp4w3z6fqnyu8t6ct69vetsda3snd",
		},
		want: "Bitcoin WIF private key (P2WPKH, Bech32), uncompressed",
	},
	{
		name: "BitcoinWIFPrivateKeyP2SHP2WPKHCompressed",
		hashes: []string{
			"3H1YvmSdrjEfj9LvtiKJ8XiYq5htJRuejA",
		},
		want: "Bitcoin WIF private key (P2SH(P2WPKH)), compressed",
	},
	{
		name: "BitcoinWIFPrivateKeyP2SHP2WPKHUncompressed",
		hashes: []string{
			"3H1YvmSdrjEfj9LvtiKJ8XiYq5htJRuejA",
		},
		want: "Bitcoin WIF private key (P2SH(P2WPKH)), uncompressed",
	},
	{
		name: "PostgreSQLSCRAMSHA256",
		hashes: []string{
			"SCRAM-SHA-256$4096:IKfxzJ8Nq4PkLJCfgKcPmA==$iRw3qwTp18uaBnsTOEExbtgWdKeBMbSSnZvqD4sdqLQ=:hPciC1CcnBna3szR8Mf3MVc8t0W7QPbIHoMMrh4zRV0=",
		},
		want: "PostgreSQL SCRAM-SHA-256",
	},
	{
		name: "AmazonAWS4HMACSHA256",
		hashes: []string{
			"$AWS-Sig-v4$0$20220221T000000Z$us-east-1$s3$421ab6e4af9f49fa30fa9c253fcfeb2ce91668e139e6b23303c5f75b04f8a3c4$3755ed2bc1b2346e003ccaa7d02ae8b73c72bcbe9f452ccf066c78504d786bbb",
		},
		want: "Amazon AWS4-HMAC-SHA256",
	},
	{
		name: "Kerberos5etype17DB",
		hashes: []string{
			"$krb5db$17$test$TEST.LOCAL$1c41586d6c060071e08186ee214e725e",
		},
		want: "Kerberos 5, etype 17, DB",
	},
	{
		name: "Kerberos5etype18DB",
		hashes: []string{
			"$krb5db$18$test$TEST.LOCAL$266b5a53a6d663c3f69174f3309acada8e467c097c7973699f86286a6cf1a6c7",
		},
		want: "Kerberos 5, etype 18, DB",
	},
	{
		name: "sha1$Saltsha1utf16le$Usernameutf16le$Pass",
		hashes: []string{
			"339b5eaa53f28516008e9ca710857d3a4785b6fc:8ca064ff42fcab5a8f0692544b8dd3d3054bd73fe9afaa08c6b6b310538cc9a7:757365726e616d65",
		},
		want: "sha1($salt.sha1(utf16le($username).':'.utf16le($pass)))",
	},
	{
		name: "FlaskSessionCookie$Salt$Salt$Pass",
		hashes: []string{
			"eyJ1c2VybmFtZSI6ImFkbWluIn0.YjdgRQ.1OTlf1PD0H9wXsu_qS0aywAJVD8",
		},
		want: "Flask Session Cookie ($salt.$salt.$pass)",
	},
	{
		name: "Radmin3",
		hashes: []string{
			"$radmin3$75007300650072006e0061006d006500*c63bf695069d564844c4849e7df6d41f1fbc5f3a7d8fe27c5f20545a238398fa*0062fb848c21d606baa0a91d7177daceb69ad2f6d090c2f1b3a654cfb417be66f739ae952f5c7c5170743459daf854a22684787b24f8725337b3c3bd1e0f2a6285768ceccca77f26c579d42a66372df7782b2eefccb028a0efb51a4257dd0804d05e0a83f611f2a0f10ffe920568cc7af1ec426f450ec99ade1f2a4905fd319f8c190c2db0b0e24627d635bc2b4a2c4c9ae956b1e02784c9ce958eb9883c60ba8ea2731dd0e515f492c44f39324e4027587c1330f14216e17f212eaec949273797ae74497782ee8b6f640dd2d124c59db8c37724c8a5a63bad005f8e491b459ff1b92f861ab6d99a2548cb8902b0840c7f20a108ede6bf9a60093053781216fe",
		},
		want: "Radmin3",
	},
	{
		name: "TrueCryptRIPEMD160XTS512bit",
		hashes: []string{
			"$truecrypt$87914967f14737a67fb460f27b8aeb81de2b41bf2740b3dd78784e02763951daa47c7ca235e75c22ec8d959d6b67f7eedefad61e6a0d038079d3721a8e7215e4$15671e8c7b3dbed6453a114e6db89a52be9a9c1698a9c698f1e37f80d7afaf0efba82b6e5f5df32bd289b95343c6775e2c7f025ef1d8bfae84042a92546e15b635b5fade3aef6ee52a7a5ab018d33ea98bc115dfc62af606187fbab8cbda6e8417402c722ca8c2b07e6ca6a33bf94b2ce2a819a9f8cfaa5af70e3af6e5350d3a306f036f13ff5ba97d5728d5f6413b482c74f528211ae77b6c169215c5487d5a3ce23736b16996b86c71b12d120df28ef322f5143d9a258d0ae7aaa8c193a6dcb5bf18e3c57b5474d24b843f8dd4e83a74109396ddb4f0c50d3657a7eacc8828568e51202de48cd2dfe5acbe3d8840ade1ce44b716d5c0008f2b21b9981353cb12b8af2592a5ab744ae83623349f551acf371c81f86d17a8422654989f078179b2386e2aa8375853a1802cd8bc5d41ce45795f78b80e69fcfa3d14cf9127c3a33fa2dc76ad73960fb7bce15dd489e0b6eca7beed3733887cd5e6f3939a015d4d449185060b2f3bbad46e46d417b8f0830e91edd5ebc17cd5a99316792a36afd83fa1edc55da25518c8e7ff61e201976fa2c5fc9969e05cbee0dce7a0ef876b7340bbe8937c9d9c8248f0e0eae705fe7e1d2da48902f4f3e27d2cf532b7021e18",
		},
		want: "TrueCrypt RIPEMD160 + XTS 512 bit",
	},
	{
		name: "TrueCryptRIPEMD160XTS1024bit",
		hashes: []string{
			"$truecrypt$d6e1644acd373e6fdb8ccaaeab0c400d22eaa0b02e2a6649e065ad50f91e2f81fc5e1600d1cdf3b4ee72a7326a9a28d336ec65adf2d54661e1a609dd9941279f$d64a9c513dfb0192734fc1e1014cdd0a399e89a0860c4077463c18609f5218254edd998adb11a02271723d1aa094550df385dd8e080cb42ed1349f69c0a6bad4b37e6dab1effbe0095471a8d640679422fe1533a21f10cb6d15e5ee8cde78e677acf3d09d008e9fbf57f09c1c57f19e51ff54631e0e2adc2ee2832425c1ec718d96a17df7e55aceffb7b23a1872f32795d4491c739e21b01e19a1b7dfcb22709c9d9302154462664a668ea635664df65804bf680ff07026d6f5b225762a3a270df832d47e7feb6277a228454a3ba9b5bbade23ecaec0eaf31ad1dbac31754c970a212bd44c9278bc6076f096a2eed602e04a70c6f7fa94ef4e75299692e5dcc6f1a7e6032b9b765e9e61faeed3f9efacc0a15b1817e74d48ec11a13d15811c7e2c4d12f36d35a04131d02f14184fc15bc20e79115dc7c980b681a19a225964469787df481b68a8f722f2bd3115dbbcb3c8ac1b07d742f78f30635dea29dfb1db83e89fc85a30b0379fc8aa69a4ea94c99052685d38c9559a1246284cdc32c5110eb8c6741352cd42e09e6389d4765c58aa84d51867cf86fba69d29eac1cd7fac2f36603d2fb2af146c5d4c2bedb4f6c6d0f387f0a8d635e33384df60f8d2415b",
		},
		want: "TrueCrypt RIPEMD160 + XTS 1024 bit",
	},
	{
		name: "TrueCryptRIPEMD160XTS1536bit",
		hashes: []string{
			"$truecrypt$3916e924d246e5ceb17b140211fff57b67150b3dee53fa475261d465b0ee3e56ee820e6ba3958d84c61508f028b2a112e9005877784e07deddcf310d01ba8171$0b620533790456d20d17c8fda84f9d93bbfe41509b931a417b82d68ed9b0bc9641b79a5bf8f71bcdbba979dfb7566a5b8ccc221f80722c1ce7ec81be4a8c880b1b057e681c187504eabf4eea32f7b81383defd4616618a99852d1678a6520883c8f3564e6dcf874150a060b9a44748d97f95b223b089ac847e31fb5a2db3656d7b57decff65e2c5c9af5bdece7a1845caa9df805fc1f7e56bf545d854beec27a9640bf1697c195e5f95b82c20d76c5a56ff4283219caa5a618e8caace9d0fcde0df6ee6e043ccbc78fd06a602cc638f7ae4675063b840ee08ffa9e143553bffd20126fa30f95e013aabf103f12c3ceeb284c80dc335fe2e78580d6ddfa80511aba9db7c93838cae0db40b9dbeccbf9d160032d334a9c35156721c746b51131baf6855fdfc1edee3099b8e4abc619e1c60e3ce68615e1eb42bd8d338046f7c854a60defe395e0d7168786a3035c9735cd42433dd0c46dcf8b5cb2c28905df80476561e55d6310b25f74d78b651ccd3484332c59a6ad490e29ea267db5ce4a47c9dcde39f420ba0755ea7e5583a3a562925acaa125d5056795b98135825232aa543a460137cc84235b85dd44d65e01e6eb1ade1b970f3ffe2b9762f5a7f261037e",
		},
		want: "TrueCrypt RIPEMD160 + XTS 1536 bit",
	},
	{
		name: "TrueCryptSHA512XTS512bit",
		hashes: []string{
			"$truecrypt$5ebff6b4050aaa3374f9946166a9c4134dd3ec0df1176da2fb103909d20e8b3c9b95cbbd6d1a7ad05411a1443ad6254e059e924d78bab6a0463e71cf7c3109b7$ef4e837bf6d7a548dd8333c451b59d1132098f44c6ff19c6cb921b1de3bd0aa675e0478a05f90204d46a5d6ff598bfa40370ac8795928a6d2e0f1347696e3cfa329738170fe54298981d84f40c63d1a338c5db62679338e849124a28a79a8e505bb89a4673f0457b2737a00b908116310281b5b2eb66c6fda5599196b313d51ef26201335d715c18f6b128454a5601671e619bdcce8e54acb47d498c4161614a05063bff5497a4a3d99bff1fce2a163727af2fe9ae7512461b9dcebf3a4f1031d6235d8ce09b734294d0cedc04eafc6295f212b1b080e7b9745580d0dd18e99cfd95afef982762d5aabeaa2d3a928dcf36322cc06b07fd719c88e0b9a2625a94a77502d4bd40a85ba138cbd0cf9561aa395dc552801f68cce16e5484a672aa5b78665dc531ab1e3e728185929dc443b7f4c8a5cb687c6589bb3f4ddc2a8639d959b839b0813d50e7711b761622c3693a92e540e4f932c6c89bf4e1bff1d69151848c3d01b2f6aba52b58e5b393f6cd58ff0d2e040b1205b042b5a28d5b12cb0cc95fa32f1bcdebd4c82d889a5d87c45dcfd34e80b19bf7be35696e0fa0cbd9338b314de24c1ee7bbc0a3b6824f86af2aa5d127d21444985ff566e921431938f6",
		},
		want: "TrueCrypt SHA512 + XTS 512 bit",
	},
	{
		name: "TrueCryptSHA512XTS1024bit",
		hashes: []string{
			"$truecrypt$9f207bec0eded18a1b2e324d4f05d2f33f0bd1aeb43db65d33242fa48ac960fad4c14d04c553e06ad47e7e394d16e0a6544d35fb0b2415bd060bc5f537e42a58$b1681e991e2ec0b5773f6e8e5766e5fcc7335b19dd068d1f20260085ecda8eba366ff1521997c5654630ef09ba421b871a3dc66aa0dd5eba8a3bc7052398a7ad779506d86cbf687e76cd9dc50969e222820d2f905c0550995a9c068725bb6c8b04358c965ab77221fdfd829e57ce54cac6e2fa62db15043d720b72fa8962dd718a0b42c34577af9cb4a5ed04c1ae17b7af470c0d8b77987dc9e2d2593a52458c4acb83b628b1488371de85f78a2e25aeaebc18d20a8c3007d08949e93b80087707afd1fe4e07a0afee4244e5270f768e234b86852aa1556c53ffc0d6f60661369a484d55d063119e71e70af1ec775908466cac7b12bc22e1a9525c2bfa9f83f7901c8e0a1d56387ef65040b750656b0b75791738b5b7e453f24167eae56c057c94e1e4cf1a0d08894225f11b45bc31827cad1dfe62e148549385953aa16a0410dba231aace3a7b9fd9b1c2b930f01193377b59736d8a8959ca5b449655f79a4dbec0da566083f90caa2490b01a10c0a86dd4aaa719bdc1e4233db17217f03509cc20dab7246730e3f964944990690b6dcc84936e1dd487bd154ceefe58a838a0488cc93b854a112ea67f6802d2f409915e648ee5cf5fdc3c12e41acbfab7caa9",
		},
		want: "TrueCrypt SHA512 + XTS 1024 bit",
	},
	{
		name: "TrueCryptSHA512XTS1536bit",
		hashes: []string{
			"$truecrypt$721a7f40d2b88de8e11f1a203b04ffa97a1f5671623c6783f984cc7c55e04665f95a7f3fd52f402898aaaed68d048cc4c4fabf81c26832b589687dad082f3e4e$0f23c7caba28118f21a4cbb8f32b25914ff4022e7c4c8cdd45411801c7c6bde4033badbdcb82f96c77b42025d13fa71415b3278138100ea58ee4476c81ce66f78e89c59ac22cf454684ea7e8c3900374662f23c9491891b60ed7ce8231a7ac5710ee87b51a3f7bd9566a60dc6e7e701c41f3810d7977314b321e8194349909f2ca458a976851d854eaeb934c8df2b5e063d416d3d7c464e28173a0bbba88ec75cf8fe68f21067739b2473bd804fd710de1e4d3ae9451b374edcfd8e3cd613b23aeae272e0923007482dac26a7532ab09af8aad57cd7f1c451bc260cc912d5830cb0d5332f792519e009ed5450171434e5f0f2ba9e003676933a86d83c766419fac98a7ee232eeb593d1686528fab576d5f393d82f9602bcd65975153df205b6d1bc50dacad2ea5bb184696f978efd2b1c1656bf87e03a28a536c48320c430d407ff6c2fc6e7d4ae7b115e79fd0a88df08eca4743178c7c216f35035596a90b0f0fe9c173c7d0e3d76c33a8fce1f5b9b37674bd12e93fb714c9cbba6768c101b5db8f8fd137144453f00dccc7b66911a0a8d87b198807f30be6619400331c5746d481df7ad47a1f867c07f7b8cd296a0c5e03a121c1a7a60b4f768bea49799d2f",
		},
		want: "TrueCrypt SHA512 + XTS 1536 bit",
	},
	{
		name: "TrueCryptWhirlpoolXTS512bit",
		hashes: []string{
			"$truecrypt$cf53d4153414b63285e701e52c2d99e148c6ccc4508132f82cb41862d0a0ac9ea16274285ac261c339c1508eec9fea54c33e382458662913678f2a88a84959a6$78e238973985ec670d50252677430587ee28b72bfa5edfb2f79c40b734ba8a54a3662642a6ab067e75f41154688ad4adb5d6decd891462dd537188195a51e06fa5baf22b69d0f472cfeeae77ab9a90091731863af1d8b5b380da179fa7d5227ef031732b1ae06e0fe34c0b28b7a64eac34e5a08e09d7001394b3afc804ac69bf819cdd2d383fe96a721f7c683628da8e529d84bdaa68d702573d8f7ef26f75d1bd5c91efa88cb33b1e9c006b87981c55ed3b8063ab7068f8e99b128bc56ea3e883efa55d6f340b2681e50405d91f5f6d76cdbeac404944164d329d3ee01311de0bc6547310f126b5a4c0e9fb74825f91faefa60b7ac828819d4544c1872ff5041e61d5cf093553f427358b2181046376d7b876e1bccf0774d5d251b7c922c214bb5c70c715165d028e1dca73e7adeca3396d77f6e597a10dd4c58f37fdbbdc1d04cd8890ba4c5025776a88a349bb925add13193becf1ca10fe32536db0c0b06a1ef799fb692e304b3716ca5a8a80859c4012ca3e06701b46b5a32f4d10e285a0cdaf6c24e0d98139e7f306e52503c9b503aa28f1fbbb236284907068074fcb3e267e3c4aab2bd3b79b24a7a08106bb55850fa2bb8e2f6d9919a6743cb822c164",
		},
		want: "TrueCrypt Whirlpool + XTS 512 bit",
	},
	{
		name: "TrueCryptWhirlpoolXTS1024bit",
		hashes: []string{
			"$truecrypt$e9e503972b72dee996b0bfced2df003a54b42399e3586520cf1f69475ba32aff564e40e604a505af95ce15220f558ae815e94ce4953882a8299ee3fffb12e9bd$62bf8e2c41c0a8337ce20d45715440cc83e394200d351c5b04be5b70fa11b8467320a091a1d703c88cc7b26fd114795c04a973b3266ba97f55d4b4e4771bb1b4a6aabc9d57e03f0ae7c8a77dfc3d37078efba45031e7d63bb514726e2f2dc6da8cce167a17e36b32c326a5bcaa2c4b445f6e10e1f899a9adcc2a698769f900b7909f7aec52fc9862d75286ffda67933f9c52e5c681d590ad0329b85f8db0f6bb6daa3b2d55b62c65da37e3e7fcb99954e0abe20c39724e8fb2c7f839ec67d35f151dfd8c4dd4bc8dc4393fab291efa08cc0099277d219a0ba4c6272af3684d8043ed3f502b98e196dc7aa0291627613179199976f28eff08649acf70aa0c0dc5896ed13eb18ea28fdd6c460a9c7cfedeab5ac80a3c195226cfca094a7590fa2ae5ed2133ba09b5466b2049b6291f8dcf345e5718a4c0ef3f9c8d8e07d0e5dddd07452b533fbf243ef063fb6d26759ae725d8ca430f8cf17b86665d23bdff1c9dbdfe601b88e87cb7c89f23abc4a8bb1f0b7375cc29b1d81c950ffe92e16e2080e1d6270bbb3ba753322d2b623caed87213e552c33e699d4010f0f61df2b7f460d7cd82e70a711388f1c0b591d424259d3de8b3628daf62c6c5b71864eb0e7d31",
		},
		want: "TrueCrypt Whirlpool + XTS 1024 bit",
	},
	{
		name: "TrueCryptWhirlpoolXTS1536bit",
		hashes: []string{
			"$truecrypt$de7d6725cc4c910a7e96307df69d41335e64d17b4425ca5bf1730f27820f92df9f20f3e855d8566eb5255927153f987348789666c8e563e366a09e68a8126b11$c25ac817b2706dde5cec3946e64332b21b41b928985c1a637559ead5b4fecac74ff0d625ef6d8be93dea3eaca05394f23ee9e079d3504a77b4c0b22d3cfcafa9c670966bfa3a5f30539250d97267a9e56b5a1437b1fd2ce58f4ab78b52ba61d01c28d7a6b726d92c8819711c70f820690cf2b9bbef75f196ba87fb5f72a29e213096a8be3b6e6d0ff3dc22563dc9e7d95be68ad169c233289fccfdc2f5528c658cb178b4e78d54e96cb452859b01dd756ca0245bdd586fb450e84988071428c80af0a6dc5f16dea8094da3acb51ac5d2a710414256b2423e0333584437ea9a65a07f06bd241103a478d137e9a274a78a19d3ca121f1bc10e4c9e5fc277d23107db1fb447f71ba0f92b20e3ead77cffaca25f772182705a75e500d9aab3996bfda042f4bdfe35a3a477e355c76a711ad0f64848d6144073ce6ec4152c87973fc3e69626523463812061c51f51fc08487e8a4dbae1ca7965c11f222c607688b3384c5c29d4fe91d14d2cc940a6a9d94486d1823261928d88f56fe00e206d7a31734de0217afd38afa3d2cf3499c2dcff13332a369c4b1f39867f6dfc83ec32d19b931b082f07acac7e70bdd537e8432245c11662d89ec3cc97e582de5d2cc6bde7",
		},
		want: "TrueCrypt Whirlpool + XTS 1536 bit",
	},
	{
		name: "TrueCryptRIPEMD160XTS512bitBootMode",
		hashes: []string{
			"$truecrypt$2b5da9924119fde5270f712ba3c3e4974460416e8465f222149499908c2fca0a4753b581f26625d11c4d3f49bdeb1c95bc3e17629d7e19ffb66175e5feab90a4$fd670194f95d578266f3f54e61b82dc00efc2bb4438e19c3f6d7a92825a7625d88ec6286ab4e1761749edc83dad4340fd167544f09913fd6b03775013ff232fc4dad6f726ef82ad4bd1c5227a7796d7db35a912beeda5b0cdd798bc34d3ac24403c87dc672a983687dd64f920c991840a56105a6311797eed9976014909700366420673f6455242c71151ac75903a353538ec24b4feb967e2b46886395cf3e934e83a6a58ef2c0180273a0c33ba2bd870b1d84afb03d5558dc17bc7fb586404ad9a7e506ed859540110c6ad73f0f1d2be47829bc666e1838ec3f1dc1f610206241ce07fbf2542ecef9348b37aa460815794ca582709697cbf0c90c3dae4cb9dd97b29d3c7d82bd8d0c81d708e74c7007468c6c55a40fd4f803a4f5a75818d7da0d1ef333b8622e7de516fa62a6fa2b8d6d5d23653dfcedffec771456ee204e5c85ee88defbe195462fbe8ce0e2a5a455dab66478b877ec37dfa66f19ab5201c56cd707ba7bee1b10360965d3868c1fdf91dda124b1b0994fee75848083d19369735905bd2864b496c6e35ecf96f6dd4728570a45746bcf8d7d0ec0b9b0b112b28fdc53efcfa7d0558c132cd683a742d62b34304d9f991029c8aedc3d8767da8c",
		},
		want: "TrueCrypt RIPEMD160 + XTS 512 bit + boot-mode",
	},
	{
		name: "TrueCryptRIPEMD160XTS1024bitBootMode",
		hashes: []string{
			"$truecrypt$debcc3e74a7b2acb4c7eaa4ac86fd6431da1d9579f4f76f0b31f07b3d36e65099daca9e4ae569114b3cb6e64d707b6206a2ab6b31ab0c17b356da3719d0e2fa4$058f0349763970855d4c83b02a967bb2969f1b6f3e4fdbce37c6df203efbe87bfdb5ffd8fe376e9ad61862a8f659ef0db39e06ed34c4f80aa856df2219ac6a37ebb0244445db7e412b773f4e28846c5e65129cd4f4ce76979c083f08a7c4e2be30469b8363eaf8579baa870cdcb2bdca6b60e64559cb0def242576b80722bf36eb6d94640d2937b49edf9c9af67f0172f27319448425f86831c35ae35e764b9e69fcc47a42ba7a565d682366023291b1b4cbcd1b7ba6fba75c214e5849a9ba26197f7f010f01301dcbffaa7311f2ab32c2810470d3fe873334ca578adbfd04c5a39cbd53b09755e4d868dbf8a44d76cc91031f4710b8a985c70738b443572b4745ed10e6120852870b0fdb258f0a804d679eec85b5290235c9c526165b961f17ff0fe32d9f597c8f2ab9b84f3d22fef71fec67987e687590de6ab11b33f1b06f23c38ead94c3de419061b6568612c27517b0a3395e401a2c6058fc5f41f0e084e8f2157b6486624314b1f341f74cfdec9deaed7abf89ccf97b47441493e5086f1351f42a5c0929f6431753baadcd2fb347b8835d08250743bb45aaf1c6bb30eed98e911a273074b7e8ebad2174b527b1b84e1961967bf358711346482d9db1c7",
		},
		want: "TrueCrypt RIPEMD160 + XTS 1024 bit + boot-mode",
	},
	{
		name: "TrueCryptRIPEMD160XTS1536bitBootMode",
		hashes: []string{
			"$truecrypt$5e6628907291b0b74a4f43a23fb0693acb71c4379c3a3cc0eafbab40036bbdadfede179e04484aca0f5b6ecf7c7e8abe61d6836be6590838b8f9027da93ba77d$076b9a557c958159c5dcddfb70823b7e324bd99b40a8f39410f6afd279df3493b58b9ffce41b65f3afd2fc467f4553a946b85e6ffc74b91c9c38c689d98419339a84d3c6d116274e34482d546407006ee04af03b594998127b2a9716ca4278b1f3050d015af10a9bb11db0465373f3a786c148bb20473377d8e97264b1c4d7ec4179829ce929573b26e5987b59da8591e2dc8e3934830dd0b5ac521c8637e9bb31e4bc084d53bc6a8dc6875e857a4c8c32a577eed3c6cea5beef514160982be2c7d7e2f4d65efa3f4a0e11ac1860ff3160e7cd968e18019abfd0395080a9f8e860c627fc32c63c8b7ef46b203c63cf0f12c05ea65b1f83a5f1fc6ad6cc200a9527151c2b8016a38f1e87be9c960088eaaa98a01d9db8cdacaae26c446a846042a6c0248b666eea7a1be44dc3fc35ce100c3a3eb377e898deb097cfba9246685d7ec8527cdc5e1983c154169178e3d86cd4017606ccc42d25cbdea0aca2b1ac422372cfbb1ad2b7d465449a2c1fbbae35c8e7fdaadd683a7dc991b76aaba08b8706916924407392a2aef458c2e833290dc1ff116f3f49f918e6a133b60728ac7c464e4f3521784cf32866be32877534bb014312c4301d1740781221a5e8758ea4",
		},
		want: "TrueCrypt RIPEMD160 + XTS 1536 bit + boot-mode",
	},
	{
		name: "VeraCryptRIPEMD160XTS512bit",
		hashes: []string{
			"$veracrypt$531aca1fa6db5118506320114cb11a9f00dade61720533fc12982b28ec71a1a3856ac6ee44b4acc207c8230352208d5f0dc37bf755bd98830279d6befcb6001c$df025f816a0aa1baf3b9b51be00fadb451ffbe9bdfc381115eeceeef778e29a8761f853b7c99e0ea9ec452ba77677f888ea40a39cf65db74d87147690684e273313dea15ff2039797e112006e5f80f2c5baf2c11eb62cb63cfb45883f8885fc7cd5bdb74ef57ec4fe3cec5c2025364582380366169d9419ac41b6f6e878429239e52538f9698e73700b920e7b58c56a4563f5aa512e334ddc56909ac2a0ad4146833f050edd78b7954e6549d0fa2e3b26ed2a769a6c029bfa4de62d49575acce078ef035e366ec13b6092cb205e481bc822f87972bfbe4a3915fad620c4b8645e96bcc468d5804208ae251a560068a09455657f4539dc7e80637fa85fbce058ffee421a98d85b2ae1118d9bd4f24e1e810627cc9893b7166e199dc91fd7f79740530a472df0948f285293478042b28cd2caef086a6ce9d5f656f97adde7d68924ef477fdf2a0c0b107671a1f94b2906d8fb58114836982e4e130e6944df8b42288512376553a1fa6526f9e46dc19b99bb568b30269d9f5d7db2d70a9aa85371b0ac71a6f6f564aaef26a0508c16bf03934973504a5188de37b18a689a020bc37a54d2863879e12902b43bc71c057fa47cbaac1e0100696af365e8226daeba346",
		},
		want: "VeraCrypt RIPEMD160 + XTS 512 bit",
	},
	{
		name: "VeraCryptRIPEMD160XTS1024bit",
		hashes: []string{
			"$veracrypt$531aca1fa6db5118506320114cb11a9f00dade61720533fc12982b28ec71a1a3856ac6ee44b4acc207c8230352208d5f0dc37bf755bd98830279d6befcb6001c$df025f816a0aa1baf3b9b51be00fadb451ffbe9bdfc381115eeceeef778e29a8761f853b7c99e0ea9ec452ba77677f888ea40a39cf65db74d87147690684e273313dea15ff2039797e112006e5f80f2c5baf2c11eb62cb63cfb45883f8885fc7cd5bdb74ef57ec4fe3cec5c2025364582380366169d9419ac41b6f6e878429239e52538f9698e73700b920e7b58c56a4563f5aa512e334ddc56909ac2a0ad4146833f050edd78b7954e6549d0fa2e3b26ed2a769a6c029bfa4de62d49575acce078ef035e366ec13b6092cb205e481bc822f87972bfbe4a3915fad620c4b8645e96bcc468d5804208ae251a560068a09455657f4539dc7e80637fa85fbce058ffee421a98d85b2ae1118d9bd4f24e1e810627cc9893b7166e199dc91fd7f79740530a472df0948f285293478042b28cd2caef086a6ce9d5f656f97adde7d68924ef477fdf2a0c0b107671a1f94b2906d8fb58114836982e4e130e6944df8b42288512376553a1fa6526f9e46dc19b99bb568b30269d9f5d7db2d70a9aa85371b0ac71a6f6f564aaef26a0508c16bf03934973504a5188de37b18a689a020bc37a54d2863879e12902b43bc71c057fa47cbaac1e0100696af365e8226daeba346",
		},
		want: "VeraCrypt RIPEMD160 + XTS 1024 bit",
	},
	{
		name: "VeraCryptRIPEMD160XTS1536bit",
		hashes: []string{
			"$veracrypt$531aca1fa6db5118506320114cb11a9f00dade61720533fc12982b28ec71a1a3856ac6ee44b4acc207c8230352208d5f0dc37bf755bd98830279d6befcb6001c$df025f816a0aa1baf3b9b51be00fadb451ffbe9bdfc381115eeceeef778e29a8761f853b7c99e0ea9ec452ba77677f888ea40a39cf65db74d87147690684e273313dea15ff2039797e112006e5f80f2c5baf2c11eb62cb63cfb45883f8885fc7cd5bdb74ef57ec4fe3cec5c2025364582380366169d9419ac41b6f6e878429239e52538f9698e73700b920e7b58c56a4563f5aa512e334ddc56909ac2a0ad4146833f050edd78b7954e6549d0fa2e3b26ed2a769a6c029bfa4de62d49575acce078ef035e366ec13b6092cb205e481bc822f87972bfbe4a3915fad620c4b8645e96bcc468d5804208ae251a560068a09455657f4539dc7e80637fa85fbce058ffee421a98d85b2ae1118d9bd4f24e1e810627cc9893b7166e199dc91fd7f79740530a472df0948f285293478042b28cd2caef086a6ce9d5f656f97adde7d68924ef477fdf2a0c0b107671a1f94b2906d8fb58114836982e4e130e6944df8b42288512376553a1fa6526f9e46dc19b99bb568b30269d9f5d7db2d70a9aa85371b0ac71a6f6f564aaef26a0508c16bf03934973504a5188de37b18a689a020bc37a54d2863879e12902b43bc71c057fa47cbaac1e0100696af365e8226daeba346",
		},
		want: "VeraCrypt RIPEMD160 + XTS 1536 bit",
	},
	{
		name: "VeraCryptSHA512XTS512bit",
		hashes: []string{
			"$veracrypt$2be25b279d8d2694e0ad1e5049902e717f1bdf741bbd678bf307d510741b649d78c54dca46fb2c92723afd9a40769b295e66d445ec232af5bddf91481ee41256$e56b77839e8bf55265077bab405901218ac7933f74073f1208f1de72aace5da4e07d5f83ca580c0216d36c200b54570a1d58e9d8e5c98a597dec23b74a465aeac572a99af70e1a1e20fd29c7c296099e4eed5b715cb470617ea4f20140b62ec4694af67d9158deac3ce846718e10518875ce8cea0286a487a295979e67159d06e871789bf5535b75c809b340f8627e18679e3dab839a1c9823ea14a07d5cc4251b777dddb408da147c70e7cc788a01c27b0ba4f4700d3248f59fa8217874ae4958ea4518522b44f7191ec19459faef7678422adecd58777487ef54a5305ff2caaa545dcb82f7e7a3eb30bd9f7ebab542d0964a367f9c710cf26bbd704e841d591428da3486db31c57f91c6167bf99e31839363cb93bc60d755031f96f2d2c964e1d85b7eaa104985ef801a21d99352c025d7415d5b2f1aa37dc513345d0ff6a1bca92ad7b8c265f322d04f2992895de32636c9b03318cf7154632d547debc1c5e0c8f8730a045efcf3d16ff956cf803716eee22168bc5a5ab72ddb5087436722cb0f59a5b7b03bc557ffb50e8757d1a5639e2bcddd8060de4ee5535fb614b4fc159c6a39040dcbe83889b9c6fac1c9364a7bea930d916ea23fafa0fde07ef609",
		},
		want: "VeraCrypt SHA512 + XTS 512 bit",
	},
	{
		name: "VeraCryptSHA512XTS1024bit",
		hashes: []string{
			"$veracrypt$37e6db10454a5d74c1e75eca0bc8a70e67ac032357e4bd6a4315c0174cf9780f92210dfc0a3e977969f2890828d446aecc317dc40fb3162915998cc703e49257$a950a1603342913900052011a7fa85fb0b1fd4489f17237ac1a8bbfd644e871ab95a4019f14b2b938d627646b9958b530dd0739760024ad323d36962b60ba92908e55a876fc392ac2dce6a2410bcdd30a01cba90427f02ccb96e222ab1381266a6f626aa00b0f59e743c1a77433cbb28648f04c91853bdf9b8b29917b2341bf7deb013131ad228ea0c7f9435985318431dae59faff46db3726341b97a956da4ad11766124cd06644c1ba1083b36d3f380f20c272e460b958841fc23be1820ad2e0e6db66eaf4ea171035add0ab543ce8e853e3119ceb9d7f32c0948b81604b81075bcb33efe747fec300a7c68ec383d28d560cccce713c0acf51d74c0db718ba93a9e720b657dda2409adf1ce35aa7e1c0d7ed3df98dd0b6d455a355ce02bda8bea8afc0a8341ac78214efd4372b4430270009ec65badf186e5f0d815dcf597b4703af95e3bfc03313125d2a88b9bb3788b6bbc3c7212713cd584a226b155a2e6872b33730af6fba29aa3dccdb0ec35b5d6e3d981faf39c8dd35fdcff502d14736bc6a47af6e4d7f3518f8ef5e0a4e5d521589a761757f86e2bef471d9867e9b532903c479e4966dcc99189fcdfa3d676f50ccd33fb7cc0aa3e85542ff2648c9",
		},
		want: "VeraCrypt SHA512 + XTS 1024 bit",
	},
	{
		name: "VeraCryptSHA512XTS1536bit",
		hashes: []string{
			"$veracrypt$d44f26d1742260f88023d825729cc5a64cf8475d887632a2fb4a84af27af138cfadc4bcbb122f6ba68339ae8427d1f72c0c4aeef041291492ae0a7d8677d8da4$3227ae2a26d9a433076b44458b14f52766cf0e4baeb473a789180660d62e42bbea7c042379a5a74e259463e1c18381fa13aee27141264be381de71c12f8f704913f211c45fda0295e963d90fc35272e907858c0522601f6e7a73b43ff222663f149a485fc6c464e5f3b7cc0b6508f30621385365ca8a4e0bff4061f64f5fbdb11f70f19d77e56fa6ff015ad76ecaaccd759d30da05d2a6fbf00ac9673ac3c23efd339313c2a99511e928f976bf9b2664d97685498d5931af2d453edc6fb1129e324eaba64264711fbe21d0d202b3659106e8100634f09c38cd15b1b3acba79d7f31d31fe23c166392e300db09f10550c83187566dc0fdf768b872555851b34e3c15ad7e7438a72e6126c895cf1204987df4b42cb7bc2fe03c5777867d269378c6e496df2a1a3457b907f7143a139d800868ad95e2901723c6ebb991054b4e991c67fe4c17702d9829d9dc1fe8bf4a956460721c858e31dbcbe56850a4ed31558c6ee89ba2cba2ef4bde77fed11848f9f92e0add54964a683c3686dbab4695ebc42554da922a08c6fff32cac936ea447e771aa74a689eb269ffef677294ef297600dfd73bbbb734d2968e38a98b4a8a77ff0eec8246d93b542e3521a3eb636101",
		},
		want: "VeraCrypt SHA512 + XTS 1536 bit",
	},
	{
		name: "VeraCryptWhirlpoolXTS512bit",
		hashes: []string{
			"$veracrypt$48f79476aa0aa8327a8a9056e61450f4e2883c9e9669142f2e2f022c2f85303b897d088dea03d64329f6c402a56fed05b3919715929090a25c8ae84c67dbdb36$4ebfa3e9ccc0b391c130a4c3dd6495a1d6eb5d2eab72f8009096f7475ecb736bb3225b6da144e1596d859dad159fae5a739beea88ea074771e9d0b2d7c48ae302606a60d7cff6db54f3e460c548c06a4f47dc1ac203a8c8349fbff6a652219a63f27bc76327543e22be4f8dab8e4f90a4283fbf1552119fe24114ce8869eb20ce87dd72300f7aad3f7b4a26a355f16517725449151cf0373dbd0b281f6ac753485a14a5361cc75d40928e241a6b4684658801774843238048cf8c7f2fd88950abac040e12b0c41fdcaca3702907e951ec11c061a91b3050a4855abe6f3b50b4bd0b17c4be1f5b50b873eadc2d8446cd72c4fcac576bbce3acea769f740c5322ee8c927ffd4dd11c8a9e66f06e58df2e5d4d85c13b44c412bab839c9512b7a0acdd97b37dcccc4b70854eda0f36de12d62dd10cc13bc6154103d083bf6540bc78e5d0aad5d063cc74dad4cbe6e060febda2a9fd79c238f99dcb0766ff4addcfd0c03e619c765f65b1c75d5d22c6536958bcda78077ff44b64c4da741bf50154df310d4e0724238a777b524237b9478277e400ad8146dc3ca1da83e3d2f1c5115a4b7fcdc71dd7d56ba86a2f9b721c9a4137aabb07c3c5fedcf5342c4fae4898c9",
		},
		want: "VeraCrypt Whirlpool + XTS 512 bit",
	},
	{
		name: "VeraCryptWhirlpoolXTS1024bit",
		hashes: []string{
			"$veracrypt$1b721942019ebe8cedddbed7744a0702c0e053281a467e0ed69bf875c7406407d72eb8f2aea21270e41898c0a2c14382f86e04c15e7bc019d1d9dd813eabee0a$e5173e3cb1d927859d3e6de1006335a5184ae12b4c8dc2db2b1cd785063152a776f4dc5cacc1856a919b880d704b7450f5a0e0c9521bc9b4d67213c36a50e6664a1cbcea33f997b858e654111c7e9fca74f361528e85a28880381ec2600e3c1cd508c3833dd21cc91978185cba53caefd7b3c82d219d49f0b41e536d32e8d3ce194ad7923ca742213e19dcebdbd9687979d5a594654a5c611e8b829c4019e90a3cfb14e5fd7f8ed91e0fc79eed182399f02a3e3e202d4becaa6730e1f05f99ce06ce16dba7777ccddac72e85f2d3be5ecc9c808ac273f10ceb71cad666166abc327c4061a5f47424a5b6d9d093782f34b49924342a2e8cea663446ed4232a9a415ee2dfde988fa827b06d7438fec20ad0689543c3ee4602ce3ec3806fc7d668ef7e34330edd1e077b329a7627fa3ae5c89308258a17ecefbee114c80c2ab06f8271f14de8f2d13d1d6e5a119b71a6bae88ab151f76cdb2442284bc481d0df7e2163c3acfe763d3968195450d275af9034a00184a30cefed163e636626bffe6a35df3472508a49cb2b9b4c4a95d11c5d17e4e0539e9f13112125515778bcd1c2813c62a02673663062ad60583ec6a02c8a572865829e5b8c767b285728bea4907",
		},
		want: "VeraCrypt Whirlpool + XTS 1024 bit",
	},
	{
		name: "VeraCryptWhirlpoolXTS1536bit",
		hashes: []string{
			"$veracrypt$5eb128daef63eff7e6db6aa10a8858f89964f47844acca68df82ebb2e73866fa75e3b7a53f9d2ff1ecdd1f4dc90e9c0fdf51f60d11b1992cd2971b4889edfc89$20bbf346fd7693f675b617cb9e4e9a43e6f445021068fc13453b130f2eb1d753ee83ecc61dabec293e88b62110cf6a8fab670e171f6aba2226550b54893263f5fa086b3cc41dd3db2eae07b585e5162c7a0d9723a426d408d83266c4d6018dc1b8b456d28a224033a30bfe62b1e58c2ddf596e07f7ff31849a6f5cfcc1c977b82d8484c270d44ededb0afdb781295e92968fc8cc69766af0ce1e72f02d6b4e124ba4b1af71519dcaade857bb3f371f93a350da6e65ee46c2ac782f134c75c10fe9d653fccc08c614dc362871911af8b83bdfc479f770dfe4b3c86b5d895842c53852fe4912738f848bf7c3e10b8189d25faceab9ef30b6fa0284edaa471752ac2b65335179b8d605417709f64fded7d94383618a921660d4cdb190bbb3769a8e56d2cd1ee07078ebc3b68ebeb016893f7099018e40cb326e32b29a62806eaf1a3fd382f4f876bf721eadfc019c5545813e81fd7168995f743663b136762b07910a63b6eec5b728a4ad07a689cceecb14c2802f334401a0a4fd2ec49e2da7f3cb24d6181f01ceed93ee73dedc3378133c83c9a71155c86785ff20dd5a64323d2fd4bf076bab3c17a1bb45edf81c30a7bd7dbbb097ece0dca83fff9138d56ae668",
		},
		want: "VeraCrypt Whirlpool + XTS 1536 bit",
	},
	{
		name: "VeraCryptRIPEMD160XTS512bitBootMode",
		hashes: []string{
			"$veracrypt$528c2997054ce1d22cbc5233463df8119a0318ab94aa715e6e686c898f36690b443221a18f578fb893e0db1e4b875cc711eab542e70e13b55d6aa26134e1a8d3$4f5ae6caaea7390a5e2f50130e85f9e551216dd0895f4fb0bcdec219246c249236771e1f2a1f447054d363c398ab367ed7f9574eb0611211e742f429cd53b56fcdb42d2eb183c134847dc6efc7c8293d6481aa53406f0446398591956f79ca3ce76e80208fd409d0f6f14c68312fc119ab4292972338b1457c73585ae2fc863bf202f141495de50253799cbc27010fba6de6b0a36888d12f4e3964aaaf43a830097aee7d40c5e79e5e80e7b0228a67a95bb4969dd8afa0d51d6fff340f82e824547c708b5aa59274009d7d847c53a8019e73c068c6e96a4c3c6c27d0e9f4a8c3a9c52c964eebc00128e9a539f4f569606c92bfc2d4662494a1a6aca239d73399645c86bd66b8985b5bf217b29eeba0507a388aeec85fe94f6b42a1b805ecb90a08b2c8081fe51e76bc1d97f73ae10c72a9b2db694304e04807820c088f91bb97d4585493f3e6cc392a7e56a64a66b8e11b51898b4f956d1b5fe8cf55772fd6f8c0f2a2bb2d9fef05ab2bb90f251ff2e6aa0dfffeac9e045be2ec44ebc8dd4d260748e308205475dcc2cef369e869bfc1e6d7335620c694f524260770838c768346d83af7b467cdc80814d8f55a535dbac35fc278d0d1f6101db95019cee097bb",
		},
		want: "VeraCrypt RIPEMD160 + XTS 512 bit + boot-mode",
	},
	{
		name: "VeraCryptRIPEMD160XTS1024bitBootMode",
		hashes: []string{
			"$veracrypt$a3c0fa44ec59bf7a3eed64bf70b8a60623664503eeb972eb51fa25ee921d813f8e45d3e1ab1c0088a62482bb78c6e07308d2308d3d66831505b0cb02fe214fba$c8a51cf9be2ada3c46045afa7df810f2e7b57792150de63b111a9aa78d70e25d832b3d6901aa455b32da240ff68380d66da27f4f7ccc5fadc6b3ff68e27b6d5c48e6512865e3b9fbe2a64a55454cfc333d7850603ecf8e1cf19abaaf8c1581a6fa14c5091ebe70e6338081d72d6a95b542764f3865946edc8e626e166cc2e0f6260032f8decdd98f9a82aa2b065a41e9b42ce8c33d3f935706431d19888bd5b2bd4d34d9bceb8596b15994f247169ee7f8cd34b6955362b60f37a4167c7b63bab8af65e7c592e9ba4535c255b4b3d93b302aa017ea335af20f9d9696f1eb37770ca87b0245d29887cc4611a3a43d11170219c509814eb1fc122a189c08394f22309dd48a996cbfc70cf67f76b6b19e46407a12ef001b2c360501dbd63d1c9f85132204709204992078318920b32aac917bb98d8eeefb60abef47571404d069a6df7881f8e7815c18789f23561d7d33f47e1aa97fb4a60bac0332b0e742a9b0498e5641401567615fd6dbd0fcfff07aebce0d543f2c498486f15f38dcf1dd55d7144d3fc51bf1f491798b183a84f3f49a72944c8054cdab915e19dc376ae3fa681d4afcd7b13f425e96340a696a4f11929b2e769ba207c5bf2c2976a3834c499d",
		},
		want: "VeraCrypt RIPEMD160 + XTS 1024 bit + boot-mode",
	},
	{
		name: "VeraCryptRIPEMD160XTS1536bitBootMode",
		hashes: []string{
			"$veracrypt$1a8c0135fa94567aa866740cb27c5b9763c95be3ac0b7b5c744a36e48c08ae38d6d06ae5db926c64d05295cef134fb4d8eaa96a7b5673a1439f55c8ab829390e$a945babc464e63f3aa33dcfed72c1bcf4051af13da96a2601a060d8c8be0343a7a4f0394b2bdd419b019bd10c3d39f0b6d9afd833816ee9ee5a8afada52db174a85ee029c46b706f8f96e937bb71569b65c2339a3ac8d831733888717fe08029013931ebed1fe932ceb16e52a5d54204e181057584d06991b8e9b16ba557d38f00e7c2be5ea864473e5e35d00a58b7ef8888c78d52ac1933011ca6c447bd16751024186657d1e314540e2c847115b70a51a23e61426ae09e646d715f807eed85e5c14ab2130da0ba86ddc40d3cdce035b454fceb969094d8d1b66e69f34e24d642dc244a81d163c395837d4cd9e2d581f4bb470ad4e5a2037068947f14676796f4adf208621c3db4629b3fec9a24edebfc37f97ea657295a2efbdd18fc44a0cc04f429d4da374db3ba2f3fc7dece70b64ac2c2a94ce5334b20b4251534f9ff3f60b1b252019d2617379bba68a4bc621cbd070881301beb0300bee243d113347d2f0a52fa79fb9fb349eba0056678618c006287e9730a0af32daa17841d88b99e25a9afcedd292a0592565f0ba533f1022ed4d6e51e64b98bab390fee3646133a0e02a5724bb14203fd50006e4be86544b62a9cb64188fbbf4ccd90a32022aa7c",
		},
		want: "VeraCrypt RIPEMD160 + XTS 1536 bit + boot-mode",
	},
	{
		name: "VeraCryptSHA256XTS512bit",
		hashes: []string{
			"$veracrypt$b8a19a544414e540172595aef79e6616f504799b40a407edfb69d40534e93f0bdb3187876f0b7a21739b3a9bb02bd4752eac4d2021e65a2a9413cc389964fad4$6e2cd37f337eb3fe3c75909fe9911609d084fb8c09543f949e738fc2fcfa4825ca5f1e08678e711142553f95b19ba720fa6c8ae5d325be0b36b93c1b2683b0944d2ad4e858c1d83f21a302ef721b9a570233219b9fcf95919fef9ca353af32d7ceb0b3058986c4ed9580b8058325403d45048e43d9e94a1e8fbaa0658f82f81940ea821e1bd526829ee6478a32da4095ab9e7c04dac3b6cc08f99348467a5bf068ba54d0aededdf6005c18ee37e21ee8d980cabe470be49d332661761934f5c07126001c290002587ba4b49982fefaac41b62f7e74ce943bb40a2d78094f734d1bc2aa3dedff43ee2a7b8f3525743c76194637da9ebc2794bac14601e03aa98e9118023a184970b6b8f84f546af88b81e2fde836e286b57cbcbdd7d39334860571a5cc612b77f0c51c741854abeb320bf961aea99b88798199bf826970f2b1b8027499955f68e15328080289d8cf0569057e1ed887f956ce72b14dd13a1f61134e1195d13c68d9c298ae0183107e3a93dd13ee0730f1fabe3935ee70f4c6a1923abb3e0d0c8ecf45260c1444e7e73386acf29d3239d0160e097e6193099e10cc98f61bfda49df6b0635e73a9ccc7bdcc543306b40dd12b91023f61b21418af91",
		},
		want: "VeraCrypt SHA256 + XTS 512 bit",
	},
	{
		name: "VeraCryptSHA256XTS1024bit",
		hashes: []string{
			"$veracrypt$1c3197f32dc5b72b4d60474a7a43afefb0d2e856a8fc4957c3fb1188b62cb0ca002f585c125bb33c5a5e85a665afae9fce15cb127c2fd9b5ee074a48fd95b3a5$8364dfd645968187d546443ba234f5cc40e78c4bdcd1e0c6d0a1208dd892442bc1dfe2a45bc4821e843bb6d9f4adf742c48c432daf0d4a51d42cafdfca281f0fab0caabde8005405840383bbfd8dbf227384891ffa501531549e0b9562c2dd77f0e6552d253acb20cbee9a75d17ec283a46006ee89cd53e3b538e054952ae6db7aac9f2f190590e697a2a8e22d080e88c32f4d27b5afe100647da2a5c80cfcb69e5a3db67cb2fcd86d89c1c53fab1bf3a287bb9002d092e75eb1fe6269a1603545dbf97b9d7fcc9485b6400f7b0abaccc31642cefd83f037e7314c6990c51af24ae894cc1c49a09d18f3ad91b3ef37ae5414fef280ec776d9c0bf84b2eb312c8cb0046bedf6f29b4aab30cdb34333f613000a39bf650341cbf33bdd47ba7bd9be8108a1254390b045d82b208d21aa45de7ca399f8e91845b9ffb47d9e6eeb506965622a2e842ec6897277388cbb6ca2a50117e228e84bebd98f9aba40f38dc3bce3b576cb08596836e50ef276ee3a76b8ce76735fd172e9bae284aa83e2677dac56e4624e66604a90e2e3ae704c64a0f27b51ce9e472891bbc212b4a6055e4482b2e6963507f9ffb477224372289fcfee5764a5f4bc7307a509e7c37c69b4857",
		},
		want: "VeraCrypt SHA256 + XTS 1024 bit",
	},
	{
		name: "VeraCryptSHA256XTS1536bit",
		hashes: []string{
			"$veracrypt$f421bdc1087b8319c12d84a680ceab0102e8e41c9ccffe76dbe0215dcfcb7b543f3e1bbedd099e88646823dae5bad8468b72436961ea8e0449a6b92b8bda7b9b$a1fe215e997ec3be2ee5eb3b4d47c41d50998df2f883404fb66270f72b5ce666e7d5ca7847c4a8b2762723da1ad088b0ad75c4fd2ccbbfa4e3adf091b6af4f44f5484ce0c89a5b0db0cbe99b3a9d43d7ff6c4ddbc9636cacfedb26b59340c6eb3e8c587db41fc01f10da2974af96531b2bee5f0b9818c3b86a3cac4ba20e08c49be84af65eb40d51626161f4eef187bf5776a89e791f3f5cbcfaa510df201fb2bf35ff03e81d0572af9abbed3cac82681925a3d1954440a6037df78f7a1e63bea81c852571a21fb550f9fe114b82bf7b94290e362cef233186f17396488c0f259c83c50ac4f8cc27d3a134ddc98f14c2fe0dd6e7d6f5eec63848314dc5984979eeb79df326f80ee0e7f671072117903cb72bbbce4f750fca3f008dadf532241e05913704df6ca03edb9641775c3b6e3e328fd078c6d70298512118312cab8316bb6ddc0b860952c621b2bb4cec1b3c7da9b1cb4c494fec382fe85aefdc56570b54845a14651535d261db519be0e860a4e20c30c86cff6f9de6e16b68d09a0e9593d271df2740950e65f1fb16e3fee034183e540e2a3b0f76156f06946b5d1bfc62fe0cab3daa14603a8d21eb03a4d266e965b010c265c9a0e093084d262a8c03",
		},
		want: "VeraCrypt SHA256 + XTS 1536 bit",
	},
	{
		name: "VeraCryptSHA256XTS512bitBootMode",
		hashes: []string{
			"$veracrypt$c8a5f07efc320ecd797ac2c5b911b0f7ee688f859890dd3fa39b4808eb3113219e2bf1517f46a20feba286a3f3e997c80361132262bc0dacb6e9f7088bec9f56$89a0b989ad9d4cc847170422ecd3384c9ee5ccf813fa8fe8ba4d2e6a993c99032337032b83471e9e0aa2531d85481c6d66f3a0d24688e1a17b5e81b3f68736ed05279ac05bcb83bea0c813d807e8c5547f11774c93a0e9de280c1ac5b5f170c0a4b5234f7d0d35a8ec7ec69454607cd35be24428a7be1799beed0ccd6a2af49b920446ebb0cb0bebda4a86c386fcffbb61cb93894ad74819a288c6e5b2e12111011e9f149d165b91f79897f71a96bc17c2b7a5e184147a90e9289d143b597ea98797c560e91b454461d03182f1a6c0bfd2b332829f30f0f18c8253d3194aac7996d4c401a3c1de7b266962a7dd8bc0b071a357121f00bafda835584a119f8fa23306545c413856ad3b2784b8de8ce9377f180baeb0f41590eb603110ff0a82f67349711d6f1b5d707f9c655318af88530962b9127fcf3c73b4d26319a9760cd795cd5ecba203dade9e1c79af14a9e06b9b56ce0af024e6ac582bd3ced1051fb865b55b4b6eaa65789a0c31c04cc4f2fc7b458fda188907f16810f4ce6e12a264cdcb264f1c26533758b92f585a3bbc2cac84731d74e9603d1c43b321ca36b01e5724e0e5558bcba56b57c8d59ded93c12d2664350cf6a048bcfc5d62aa85c590",
		},
		want: "VeraCrypt SHA256 + XTS 512 bit + boot-mode",
	},
	{
		name: "VeraCryptSHA256XTS1024bitBootMode",
		hashes: []string{
			"$veracrypt$6bb6eef1af55eb2b2849e1fc9c90c08f705010efa6443581111216b3e145201374bb8e626e4d94a4ce7ecabb11aa57610063fceed38ca9873b0e1194bd12121d$2f6b8a71994c5982049c4517ca7178a55b68cee773e06532b46d68810ede1b18783d7bca98bebf1778d14ecc18e0791190402c6a82bf3ec93e715e65997812363cc6e6bcad4f751fce16f37bbc1d6ac1d0a24c5685e85501a7c46d1cd5b04c55c605357906e5957b99230e2e9834a206e6ff48270ddf3c08c39e5c8390b2a7b7e6064719dbac29ef7513ea78c0edf420eb7ac6db684e890c5fcacfb230996f335f48f4472eaa33f3abe59943a8e3bc27ff4c24fd42015fdacd5e2eaf448049b4aa5ef1c038ca853871fc7f2573aace0874cdd1f3e01140803c1ad036b801cc1a54d619064b9b31e70e7e2601fd7b40f67814320c56721e86ddb3c62ec8cb9680ca7d2504b9decf360e32497ace8171dd9602f01db3be1541f659643e1bdc5139815acdf4debf0186707569c9b57c0fd0031ce03a5091d7937bca8f37015fa35af5f44968176164c0b9194f895a2346dacc51f5e3e7be5682ea7860c4b4302a0f22edecc7ccaebb1c824c5ca4ed4c5e674e742a1d55a7d3e732e40f0107ffad1e3876ec909fac58f1ee21ac99de2c8c29272b1df9dd7f724ff497925898506c4f6e2ae81e285239e5260b119af959338340876b5b8fdd6fede67ae37d3c750265",
		},
		want: "VeraCrypt SHA256 + XTS 1024 bit + boot-mode",
	},
}

func TestMain(m *testing.M) {
	var err error
	hashid, err = New()
	if err != nil {
		panic(err)
	}
	code := m.Run()
	os.Exit(code)
}

func testHashType(t *testing.T, hash string, want string) {
	results := hashid.FindHashType(hash)
	for _, result := range results {
		if result.Name == want {
			return
		}
	}
	t.Errorf("%q should be %q", hash, want)
}

func TestHashType(t *testing.T) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, hash := range tc.hashes {
				testHashType(t, hash, tc.want)
			}
		})
	}
}
