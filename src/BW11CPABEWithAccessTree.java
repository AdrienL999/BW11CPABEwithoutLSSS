import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.stream.IntStream;

public class BW11CPABEWithAccessTree {

    private static Pairing pairing;
    public static Pairing getPairing(String pairingParamsFileName){
        if(pairing == null){
            pairing = PairingFactory.getPairing(pairingParamsFileName);
        }
        return pairing;
    }

    public static void setup(String pairingParamsFileName, int[] U, String pkFileName, String mskFileName){
        Pairing bp = getPairing(pairingParamsFileName);

        Element g = bp.getG1().newRandomElement().getImmutable();
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element a = bp.getZr().newRandomElement().getImmutable();
        Element egg_alpha = bp.pairing(g,g).powZn(alpha).getImmutable();
        Element g_a = g.duplicate().powZn(a).getImmutable();
        Element g_alpha = g.duplicate().powZn(alpha).getImmutable();

        Properties pkProperties = new Properties();
        Properties mskProperties = new Properties();

        IntStream.rangeClosed(0, U.length - 1).parallel().forEach(i -> {
            Element h = bp.getG1().newRandomElement().getImmutable();
            synchronized (pkProperties){
                pkProperties.setProperty("h"+ U[i], Base64.getEncoder().withoutPadding().encodeToString(h.toBytes()));
            }
        });
        pkProperties.setProperty("g", Base64.getEncoder().withoutPadding().encodeToString(g.toBytes()));
        pkProperties.setProperty("egg_alpha", Base64.getEncoder().withoutPadding().encodeToString(egg_alpha.toBytes()));
        pkProperties.setProperty("g_a", Base64.getEncoder().withoutPadding().encodeToString(g_a.toBytes()));
        mskProperties.setProperty("g_alpha", Base64.getEncoder().withoutPadding().encodeToString(g_alpha.toBytes()));
        storePropToFile(pkProperties, pkFileName);
        storePropToFile(mskProperties, mskFileName);
    }

    public static void keygen(String pairingParamsFileName, int[] UesrAttList, String pkFileName, String mskFileName, String skFileName){
        Pairing bp = getPairing(pairingParamsFileName);
        Properties pkProperties = loadPropFromFile(pkFileName);
        Properties mskProperties = loadPropFromFile(mskFileName);

        String gStr = pkProperties.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gStr)).getImmutable();

        String g_alphaStr = mskProperties.getProperty("g_alpha");
        Element g_alpha = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_alphaStr)).getImmutable();

        String g_aStr = pkProperties.getProperty("g_a");
        Element g_a = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_aStr)).getImmutable();

        Element t = bp.getZr().newRandomElement().getImmutable();
        Element K = g_alpha.duplicate().mul(g_a.powZn(t)).getImmutable();
        Element L = g.duplicate().powZn(t).getImmutable();

        Properties skProperties = new Properties();
        for(int att: UesrAttList){
            String hStr = pkProperties.getProperty("h"+att);
            Element h = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(hStr)).getImmutable();
            Element Kx = h.duplicate().powZn(t).getImmutable();
            skProperties.setProperty("Kx"+att, Base64.getEncoder().withoutPadding().encodeToString(Kx.toBytes()));
        }
        skProperties.setProperty("K", Base64.getEncoder().withoutPadding().encodeToString(K.toBytes()));
        skProperties.setProperty("L", Base64.getEncoder().withoutPadding().encodeToString(L.toBytes()));
//        skProperties.setProperty("UserAttList", Arrays.toString(UesrAttList));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < UesrAttList.length; i++) {
            sb.append(UesrAttList[i]);
            if (i < UesrAttList.length - 1) {
                sb.append(",");
            }
        }
        skProperties.setProperty("UserAttList", sb.toString());
        storePropToFile(skProperties, skFileName);
    }

    public static void encrypt(String pairingParamsFileName, Element message, Node[] AccessTree, String pkFileName, String ctFileName){
        System.out.println("加密原始消息: " + message);
        Pairing bp = getPairing(pairingParamsFileName);

        Properties pkProperties = loadPropFromFile(pkFileName);
        String gStr = pkProperties.getProperty("g");
        Element g = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(gStr)).getImmutable();
        String g_aStr = pkProperties.getProperty("g_a");
        Element g_a = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(g_aStr)).getImmutable();
        String egg_alphaStr = pkProperties.getProperty("egg_alpha");
        Element egg_alpha = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(egg_alphaStr)).getImmutable();

        Properties ctProperties = new Properties();
        Element s = bp.getZr().newRandomElement().getImmutable();
        Element C = message.duplicate().mul(egg_alpha.powZn(s)).getImmutable();
        Element Cp = g.duplicate().powZn(s).getImmutable();
        ctProperties.setProperty("C", Base64.getEncoder().withoutPadding().encodeToString(C.toBytes()));
        ctProperties.setProperty("CP", Base64.getEncoder().withoutPadding().encodeToString(Cp.toBytes()));

        AccessTree[0].sharesecret = s;
        AccessTreeUtils.nodeShare(AccessTree, AccessTree[0], bp);
        for (Node node : AccessTree){
            if (node.isLeaf()){
                Element r = bp.getZr().newRandomElement().getImmutable();
                String hStr = pkProperties.getProperty("h" + node.att);
                Element h = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(hStr)).getImmutable();

                Element h_neg_r = h.duplicate().powZn(r).invert();
                Element Ci = g_a.duplicate().powZn(node.sharesecret).mul(h_neg_r).getImmutable();
                Element Di = g.duplicate().powZn(r);

                ctProperties.setProperty("Ci-"+node.att, Base64.getEncoder().withoutPadding().encodeToString(Ci.toBytes()));
                ctProperties.setProperty("Di-"+node.att, Base64.getEncoder().withoutPadding().encodeToString(Di.toBytes()));
            }
        }
        storePropToFile(ctProperties,ctFileName);
    }

    public static Element decrypt(String pairingParamsFileName, Node[] AccessTree, String ctFileName, String skFileName){
        Pairing bp = getPairing(pairingParamsFileName);
        Properties ctProperties = loadPropFromFile(ctFileName);
        Properties skProperties = loadPropFromFile(skFileName);

        String UserAttListStr = skProperties.getProperty("UserAttList");
        int[] UserAttList = Arrays.stream(skProperties.getProperty("UserAttList").split(","))
                .map(String::trim)
                .mapToInt(Integer::parseInt)
                .toArray();
        System.out.println("用户属性列表：" + UserAttListStr);

        String CStr = ctProperties.getProperty("C");
        Element C = bp.getGT().newElementFromBytes(Base64.getDecoder().decode(CStr)).getImmutable();

        String CPStr = ctProperties.getProperty("CP");
        Element CP = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(CPStr)).getImmutable();

        String KStr = skProperties.getProperty("K");
        Element K = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(KStr)).getImmutable();
        String LStr = skProperties.getProperty("L");
        Element L = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(LStr)).getImmutable();

        for (Node node: AccessTree){
            if (node.isLeaf()){
                if (Arrays.stream(UserAttList).anyMatch(attr -> attr == node.att)){
                    String CiStr = ctProperties.getProperty("Ci-"+node.att);
                    Element Ci = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(CiStr)).getImmutable();

                    String DiStr = ctProperties.getProperty("Di-"+node.att);
                    Element Di = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(DiStr)).getImmutable();

                    String KxStr = skProperties.getProperty("Kx"+node.att);
                    Element Kx = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(KxStr)).getImmutable();

                    Element part1 = bp.pairing(L, Ci);
                    Element part2 = bp.pairing(Kx, Di);
                    node.sharesecret = part1.mul(part2).getImmutable();
//                    System.out.println("叶子节点属性 " + node.att + " 的秘密值: " + node.sharesecret);
                }
            }
        }

        boolean TreeOK = AccessTreeUtils.nodeRecover(AccessTree, AccessTree[0], UserAttList, bp, true);
        if(TreeOK){
            System.out.println("根节点秘密值: " + AccessTree[0].sharesecret);// 添加调试日志

            Element eCPK = bp.pairing(CP, K).getImmutable();
//            System.out.println("e(CP, K): " + eCPK);
            Element root_secret = AccessTree[0].sharesecret;
            Element denominator = eCPK.div(root_secret);
//            System.out.println("denominator = e(CP,K)/root_secret: " + denominator);
            // 添加调试日志
            return C.duplicate().div(denominator);

        }
        else {
            System.out.println("❌ 访问树不满足！");
            return null;
        }

    }

    public static void storePropToFile(Properties prop, String fileName) {
        try {
            Path path = Paths.get(fileName);
            Path parentDir = path.getParent();

            // 确保父目录存在
            if (parentDir != null && !Files.exists(parentDir)) {
                Files.createDirectories(parentDir);
                System.out.println("✅ 创建目录：" + parentDir);
            }

            try (OutputStream outputStream = Files.newOutputStream(path)) {
                prop.store(outputStream, "System Parameters");
                System.out.println("✅ 文件保存成功：" + path); // 添加成功确认
            }
        } catch (IOException e) {
            System.err.println("❌ 保存失败：" + fileName);
            throw new RuntimeException("保存失败: " + e.getMessage(), e);
        }
    }


    public static Properties loadPropFromFile(String fileName) {
        if(!Files.exists(Paths.get(fileName))){
            throw new IllegalArgumentException("文件不存在" + fileName);
        }
        Properties prop = new Properties();
        try(FileInputStream inputStream = new FileInputStream(fileName)){
            prop.load(inputStream);
        }catch (IOException e){
            System.err.println("加载文件失败" + fileName);
            System.err.println("错误原因" + e.getMessage());
            throw new RuntimeException("无法加载配置文件" + fileName, e);
        }
        return prop;
    }

    public static void main(String[] args) {
        String pairingParamsFileName = "a.properties";
        File paramFile = new File(pairingParamsFileName);
        if(!paramFile.exists()){
            System.err.println("配对参数文件不存在" + paramFile.getAbsolutePath());
            System.err.println("请从JPBC库中添加参数文件");
            System.exit(-1);
        }

        Pairing pairing = getPairing(pairingParamsFileName);
        System.out.println("配对是否对称? " + pairing.isSymmetric());
        if (!pairing.isSymmetric()) {
            System.err.println("错误：必须使用对称配对参数");
            System.exit(-1);
        }

        int[] U = new int[100];
        for (int i = 0; i < U.length; i++) {
            U[i] = i + 1;  // 索引0对应1，索引99对应100
        }

        int[] UserAttList = {54, 34, 56, 65};

        // 当前结构可能有逻辑问题（根节点子节点为1,2,3但数组索引是0-6）
        Node[] AccessTree = new Node[7];
        AccessTree[0] = new Node(new int[]{2,3}, new int[]{1,2,3}); // 根节点（2-of-3门限）
        AccessTree[1] = new Node(new int[]{2,3}, new int[]{4,5,6}); // 中间节点
        AccessTree[2] = new Node(54);
        AccessTree[3] = new Node(34);
        AccessTree[4] = new Node(65);
        AccessTree[5] = new Node(56);
        AccessTree[6] = new Node(21);  // 不满足的属性


        String dir = "data/";
        String pkFileName = dir + "pk.properties";
        String mskFileName = dir + "msk.properties";
        String skFileName = dir + "sk.properties";
        String ctFileName = dir + "ct.properties";

        setup(pairingParamsFileName,U,pkFileName,mskFileName);

        keygen(pairingParamsFileName,UserAttList,pkFileName,mskFileName,skFileName);

        Element message = getPairing(pairingParamsFileName).getGT().newRandomElement().getImmutable();

        encrypt(pairingParamsFileName,message,AccessTree,pkFileName,ctFileName);

        for (Node node : AccessTree){
            node.sharesecret = null;
        }

        Element res = decrypt(pairingParamsFileName,AccessTree,ctFileName,skFileName);

        System.out.println("\n=======================================");
        System.out.println("原始消息: " + message);
        System.out.println("解密消息: " + res);
        System.out.println("解密" + (message.equals(res) ? "成功 ✅" : "失败 ❌"));
        System.out.println("=======================================");

    }
}
