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
