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
		name: "FreeBSDMD5",
		hashes: []string{
			"$1$28772684$iEwNOgGugqO9.bIz5sk8k/",
		},
		want: "FreeBSD MD5",
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
