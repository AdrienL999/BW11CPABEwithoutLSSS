import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static java.lang.Integer.valueOf;

public class AccessTreeUtils {

    public static Element[] randomP(int d, Element s, Pairing bp){
        Element[] coef = new Element[d];
        coef[0] = s;
        for (int i = 1; i < d; i++) {
            coef[i] = bp.getZr().newRandomElement().getImmutable();
        }
        return coef;
    }

    public static Element qx(Element index, Element[] coef, Pairing bp){
        Element res = coef[0].duplicate();
        for (int i = 1; i < coef.length; i++) {
            Element exp = bp.getZr().newElement(i).getImmutable();
            res = res.add(coef[i].mul(index.duplicate().powZn(exp)));
        }
        return res;
    }

    public static Element lagrange(int i, int[] S, int x, Pairing bp) {
        Element res = bp.getZr().newOneElement().getImmutable();
        Element iElement = bp.getZr().newElement(i).getImmutable();
        Element xElement = bp.getZr().newElement(x).getImmutable();
        for (int j : S) {
            if (j != i) {
                Element jElement = bp.getZr().newElement(j).getImmutable();
                Element numerator = xElement.sub(jElement);
                Element denominator = iElement.sub(jElement);
                Element term = numerator.div(denominator);
                res = res.mul(term);
            }
        }
        return res;
    }

    public static void nodeShare(Node[] nodes, Node n, Pairing bp) {
        if (!n.isLeaf()) {
            Element[] coef = randomP(n.gate[0], n.sharesecret, bp);
            for (int j = 0; j < n.children.length; j++) {
                Node childNode = nodes[n.children[j]];
                childNode.sharesecret = qx(bp.getZr().newElement(n.children[j]), coef, bp);
                nodeShare(nodes, childNode, bp);
            }
        }
    }

    public static boolean nodeRecover(Node[] nodes, Node n, int[] atts, Pairing bp, boolean isGTMode) {
        if (!n.isLeaf()) {
            List<Integer> validChildrenList = new ArrayList<>();
            List<Integer> validChildIndices = new ArrayList<>(); // 存储children数组中的索引
            for (int i = 0; i < n.children.length; i++) {
                int childIndex = n.children[i];
                Node childNode = nodes[childIndex];
                if (nodeRecover(nodes, childNode, atts, bp, isGTMode)) {
                    validChildrenList.add(childIndex);
                    validChildIndices.add(childIndex); // 记录有效的子节点索引（children数组的值）
                    if (validChildrenList.size() == n.gate[0]) {
                        n.valid = true;
                        break;
                    }
                }
            }

            if (validChildrenList.size() == n.gate[0]) {
                // 转换为int[]数组，用于拉格朗日计算
                int[] validChildren = validChildrenList.stream().mapToInt(i -> i).toArray();
                int[] validChildIndexArray = validChildIndices.stream().mapToInt(i -> i).toArray();

                Element secret = bp.getGT().newOneElement().getImmutable();
                for (int childIdx : validChildIndexArray) { // 使用父节点children数组中的索引
                    Node childNode = nodes[childIdx];
                    Element delta = lagrange(childIdx, validChildIndexArray, 0, bp);
                    Element part = childNode.sharesecret.duplicate().powZn(delta);
                    secret = secret.mul(part);
                }
                n.sharesecret = secret.getImmutable();
                System.out.println("恢复节点 [" + n + "] 的秘密值: " + secret);
            }
        } else {
            // 叶子节点处理逻辑不变
            boolean matched = Arrays.stream(atts).anyMatch(attr -> attr == n.att);
            n.valid = matched;
            if (matched) {
                System.out.printf("✅ 属性匹配成功: %d\n", n.att);
            } else {
                System.out.printf("❌ 属性匹配失败: %d （不在属性集合 %s 中）\n", n.att, Arrays.toString(atts));
            }
        }
        return n.valid;
    }
}
