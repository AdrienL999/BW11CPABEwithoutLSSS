import it.unisa.dia.gas.jpbc.Element;

import java.util.Arrays;
/**
 * 表示访问控制树中的节点（叶子节点/内部节点）
 * 用途：用于基于属性的加密策略（如CP-ABE）
 */
public class Node {
    // gate用两个数(t,n)表示，n表示子节点个数, t表示门限值
    // 如果是叶子节点，则为null
    public int[] gate;
    // children表示内部节点，此字段为子节点索引列表
    // 如果是叶子节点，则为null
    public int[] children;
    //att表示属性，只有叶子节点有属性，如果是内部节点，则为null
    public int att;
    // 秘密值
    public Element sharesecret;

    public boolean valid;//标记节点是否通过验证, 用途：在策略检查时标记满足条件的节点
    //内部节点的构造方法
    public Node(int[] gate, int[] children){
        this.gate = gate;
        this.children = children;
    }
    //叶子节点构造
    public Node(int att){
        this.att = att;
    }

    public boolean isLeaf(){
        return this.children==null ? true : false; //判断是否是叶子节点
    }
    @Override
    public String toString() {  // 返回类型必须是String
        if (this.isLeaf()) {
            return String.valueOf(this.att);  // 将int转换为String
        } else {
            return Arrays.toString(this.gate);  // 直接返回数组的字符串表示
        }
    }
}
