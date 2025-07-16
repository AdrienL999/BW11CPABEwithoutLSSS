import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import static java.lang.Integer.valueOf;

public class AccessTreeStructure {
    //d-1次多项式表示为q(x)=coef[0] + coef[1]*x^1 + coef[2]*x^2 + coef[d-1]*x^(d-1)
    //多项式的系数的数据类型为Zr Element，从而是的后续相关计算全部在Zr群上进行
    //通过随机选取coef参数，来构造d-1次多项式q(x)。约束条件为q(0)=s。
    /*public static Element[] randomP(int d, Element s, Pairing bp){
        Element[] coef = new Element[d];
        coef[0] = s;
        for (int i=1; i<d; i++){
            coef[i] = bp.getZr().newRandomElement().getImmutable();//先随机选择参数
        }
        return coef;
    }

    public static Element qx(Element index, Element[] coef, Pairing bp){
        Element res = coef[0].getImmutable();
        for (int i=1; i<coef.length; i++){
            Element exp = bp.getZr().newElement(i).getImmutable();
            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
        }
        return res;
    }

    public static Element lagrange(int i, int[] S, int x, Pairing bp){
        Element res = bp.getZr().newOneElement().getImmutable();
        Element iElement = bp.getZr().newElement(i).getImmutable();
        Element xElement = bp.getZr().newElement(x).getImmutable();
        for(int j : S){
            if(j != i){
                Element numerator = xElement.sub(bp.getZr().newElement(j));
                Element denominator = iElement.sub(bp.getZr().newElement(j));
                Element term = numerator.div(denominator);
                res = res.mul(term);
            }
        }
        return res;
    }*/

    /*public static void nodeShare(Node[] nodes, Node n, Pairing bp){//输入：整个树、要分享的节点和bp
        if(!n.isLeaf()){//检查当前节点是否为内部节点，因为叶子结点不需要多项式，直接跳过即可。
            Element[] coef = randomP(n.gate[0], n.sharesecret, bp);
            //生成多项式，n.gate[0]=kx，也就是解密所需的最小节点数
            //n.sharesecret是当前节点的秘密值，
            for (int j = 0; j < n.children.length; j++){//遍历子节点
                Node childNode = nodes[n.children[j]]; //通过子节点ID从节点数组中获取子节点对象，n.children[j]：当前子节点的ID（如1,4,3等）
                // 对于每一个子节点，以子节点的索引为横坐标，计算子节点的多项式值（也就是其对应的秘密分片）
                childNode.sharesecret = qx(bp.getZr().newElement(n.children[j]), coef, bp);
                nodeShare(nodes, childNode, bp);
            }
        }
    }*/

    /*public static boolean nodeRecover(Node[] nodes, Node n, String[] atts, Pairing bp){//输入：整个树、要恢复的节点、属性集合
        if(!n.isLeaf()){
            // 对于内部节点，维护一个子节点索引列表，用于秘密恢复。
            List<Integer> validChildrenList = new ArrayList<Integer>();
            int[] validChildren;
            for(int i = 0; i < n.children.length; i++){
                Node childNode = nodes[n.children[i]];
                //递归调用子节点的子节点
                if (nodeRecover(nodes, childNode, atts, bp)){
                    validChildrenList.add(valueOf(n.children[i]));
                    if(validChildrenList.size() == n.gate[0]){//这个等式说明有效的子节点数量已经=门限值
                        n.valid = true;//n.valid 是一个标记位，表示该节点是否有效（即其子节点是否满足门限条件）。
                        break;
                    }
                }
            }

            // 如果可恢复的子节点个数等于门限值，则利用子节点的秘密分片恢复当前节点的秘密。
            if(validChildrenList.size() == n.gate[0]){//list的长度满足门限值
                validChildren = validChildrenList.stream().mapToInt(i -> i).toArray();
                //validChildrenList.stream() 将List(整型)转为流。
                //.mapToInt(i -> i)转为IntStream。
                //.toArray();转为int[]数组。
                Element secret = bp.getZr().newZeroElement().getImmutable();//选择一个秘密0，为了恢复。
                for(int i : validChildren){
                    Element delta = lagrange(i, validChildren, 0, bp);
                    secret = secret.add(nodes[i].sharesecret.duplicate().mul(delta));
                    //这里恢复密钥，可以去看论文中笔记的例子
                }
                n.sharesecret = secret;
            }
        }
        else {
            if (Arrays.asList(atts).contains(n.att)){
                *//* Arrays.stream(atts)将att数组转换为Stream流
                  .boxed() 将原始类型的Stream转换为包装类型的Stream。如果 atts 是 int[] 或 long[]，.boxed() 会将原始类型（如 int）装箱为包装类型（如 Integer）。
                  .collect(Collectors.toList())将流转为List
                  .contains(n.att)检查n.att是否在List中*//*
                n.valid = true;
            }
        }
        return n.valid;
    }*/

    public static void main(String[] args) {
        Pairing bp = PairingFactory.getPairing("a.properties");

        // 打印标题
        System.out.println("===== ABE 访问控制树演示 =====");
        System.out.println();

        // 1. 初始化访问控制树节点
        System.out.println("【1. 初始化节点结构】");
        Node[] nodes = new Node[7];//初始化7个节点
        nodes[0] = new Node(new int[]{2,3}, new int[]{1,2,3});//根节点是2of3的门限，索引是123
        nodes[1] = new Node(1);
        nodes[2] = new Node(new int[]{2,3}, new int[]{4,5,6});
        nodes[3] = new Node(5);
        nodes[4] = new Node(2);
        nodes[5] = new Node(3);
        nodes[6] = new Node(4);

        // 2. 设置根节点秘密并分发秘密份额
        System.out.println("\n【2. 秘密分发阶段】");
        nodes[0].sharesecret = bp.getZr().newElement(10);// 根节点秘密设为10
        AccessTreeUtils.nodeShare(nodes, nodes[0], bp);// 递归分发秘密
        // 打印分发后的秘密份额
        System.out.println("-- 分发后的秘密份额：");
        printNodesWithSecrets(nodes);
        System.out.println("----------------------------------------");

        // 3. 准备恢复阶段(清除内部节点秘密)
        System.out.println("\n【3. 秘密恢复准备】");
        System.out.println("- 清除内部节点的秘密(模拟解密时已知条件):");
        clearInternalNodeSecrets(nodes);
        printNodesWithSecrets(nodes);
        System.out.println("----------------------------------------");

        // 4. 尝试恢复秘密
        System.out.println("\n【4. 秘密恢复阶段】");
        int[] AttList = new int[]{1, 2, 3, 4, 5};
        System.out.println("- 用户属性集合: " + Arrays.toString(AttList));
        boolean res = AccessTreeUtils.nodeRecover(nodes, nodes[0], AttList, bp, false);

        System.out.println("\n- 恢复后的状态:");
        printNodesWithSecrets(nodes);
        System.out.println("----------------------------------------");

        // 5. 输出最终结果
        System.out.println("\n【5. 最终结果】");
        System.out.println("- 秘密恢复" + (res ? "成功" : "失败") + "!");
        System.out.println("- 根节点恢复的秘密: " + nodes[0].sharesecret);
    }

    public static void printNodesWithSecrets(Node[] nodes){
        for (int i=0; i<nodes.length; i++){
            String type = nodes[i].isLeaf() ? "叶子节点" : "门限节点";
            System.out.printf("节点%d [%s]: %-6s 秘密份额: %s\n",
                    i,
                    type,
                    nodes[i],
                    nodes[i].sharesecret != null ? nodes[i].sharesecret : "null" );
        }
    }

    public static void clearInternalNodeSecrets(Node[] nodes){
        for (Node node : nodes){
            if(!node.isLeaf()){
                node.sharesecret = null;
            }
        }
    }
}


