package rules;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTAssignmentExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTMethod;
import net.sourceforge.pmd.lang.apex.ast.ASTModifierList;
import net.sourceforge.pmd.lang.apex.ast.ASTParameter;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableDeclaration;
import net.sourceforge.pmd.lang.apex.ast.ASTVariableExpression;
import net.sourceforge.pmd.lang.apex.ast.ApexNode;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;

/**
 * Custom PMD rule to detect unsafe variables in SOQL queries (SQL injection risk)
 * Priority: 2 (High)
 */
public class ApexTaintSoqlRule extends AbstractApexRule {

    private final Set<String> taintedVars = new HashSet<>();

    @Override
    public Object visit(ASTMethod node, Object data) {

        // Mark parameters of public or annotated methods as safe
        for (ASTParameter p : node.findChildrenOfType(ASTParameter.class)) {

            ASTModifierList mods = node.getFirstChild(ASTModifierList.class);
            boolean isPublic = mods != null && mods.isPublic();
            boolean hasAnnotation = !node.findChildrenOfType(net.sourceforge.pmd.lang.apex.ast.ASTAnnotation.class).isEmpty();

            if (isPublic || hasAnnotation) {
                taintedVars.add(Helper.getFQVariableName(p));
            }
        }

        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTVariableDeclaration node, Object data) {
        checkAssignment(node);
        return super.visit(node, data);
    }

    @Override
    public Object visit(ASTAssignmentExpression node, Object data) {
        checkAssignment(node);
        return super.visit(node, data);
    }

    private void checkAssignment(ApexNode<?> node) {
        ASTVariableExpression leftVar = node.firstChild(ASTVariableExpression.class);
        ASTVariableExpression rightVar = null;

        // get first ASTVariableExpression child from descendants
        for (ASTVariableExpression v : node.descendants(ASTVariableExpression.class)) {
            rightVar = v;
            break;
        }

        if (leftVar != null && rightVar != null) {
            String fqName = Helper.getFQVariableName(leftVar);
            if (taintedVars.contains(Helper.getFQVariableName(rightVar))) {
                taintedVars.add(fqName);
            }
        }
    }
}
