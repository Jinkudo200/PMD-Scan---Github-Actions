package rules;

import java.util.HashSet;
import java.util.Set;

import net.sourceforge.pmd.lang.apex.ast.ASTMethodCallExpression;
import net.sourceforge.pmd.lang.apex.ast.ASTUserClass;
import net.sourceforge.pmd.lang.apex.ast.ASTMethod;
import net.sourceforge.pmd.lang.apex.ast.ASTModifier;
import net.sourceforge.pmd.lang.apex.ast.ASTAnnotation;
import net.sourceforge.pmd.lang.apex.rule.AbstractApexRule;
import net.sourceforge.pmd.lang.rule.RuleTargetSelector;
import net.sourceforge.pmd.lang.apex.rule.internal.Helper;

/**
 * MEDIUM priority
 * Detects:
 * - Classes/methods without 'with sharing' accessing SObjects.
 * - Public/global methods exposing sensitive functionality.
 * - Weak or missing authentication checks in REST/Webservice methods.
 *
 * Related OWASP Top 10: A1, A5
 */
public class ApexWeakAuthAndSharingRule extends AbstractApexRule {

    private final Set<String> violations = new HashSet<>();

    public ApexWeakAuthAndSharingRule() {
        setPriority(3); // Medium
    }

    @Override
    protected RuleTargetSelector buildTargetSelector() {
        return RuleTargetSelector.forTypes(ASTUserClass.class);
    }

    @Override
    public Object visit(ASTUserClass node, Object data) {
        // Skip system/test classes
        if (Helper.isTestMethodOrClass(node) || Helper.isSystemLevelClass(node)) {
            return data;
        }

        boolean withSharing = node.getImage() != null && node.getImage().contains("with sharing");

        for (ASTMethod method : node.findDescendantsOfType(ASTMethod.class)) {
            boolean isGlobalOrPublic = isGlobalOrPublic(method);
            boolean hasAuthAnnotation = hasAuthenticationCheck(method);

            // 1️⃣ Global/Public methods exposing sensitive data
            if (isGlobalOrPublic && !withSharing) {
                addViolation(data, method, "Global/Public method in class without 'with sharing' may expose sensitive data.");
            }

            // 2️⃣ Webservice/REST methods without authentication
            if (isWebServiceOrRest(method) && !hasAuthAnnotation) {
                addViolation(data, method, "Webservice/REST method missing authentication check. OWASP A1/A5 risk.");
            }

            // 3️⃣ Detect direct SObject access without sharing enforcement
            for (ASTMethodCallExpression call : method.findDescendantsOfType(ASTMethodCallExpression.class)) {
                String def = call.getDefiningType() != null ? call.getDefiningType() : "";
                String m = call.getMethodName() != null ? call.getMethodName() : "";
                if (("Database".equals(def) || "SOQL".equals(def)) && !withSharing) {
                    addViolation(data, call, "SObject access without sharing enforcement detected.");
                }
            }
        }

        return data;
    }

    private boolean isGlobalOrPublic(ASTMethod method) {
        for (ASTModifier mod : method.findDescendantsOfType(ASTModifier.class)) {
            String image = mod.getImage();
            if ("global".equalsIgnoreCase(image) || "public".equalsIgnoreCase(image)) {
                return true;
            }
        }
        return false;
    }

    private boolean isWebServiceOrRest(ASTMethod method) {
        for (ASTAnnotation ann : method.findDescendantsOfType(ASTAnnotation.class)) {
            String name = ann.getImage();
            if ("WebService".equalsIgnoreCase(name) || "RestResource".equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    private boolean hasAuthenticationCheck(ASTMethod method) {
        // Heuristic: if method calls UserInfo.getProfileId(), UserInfo.getRoleId(), or checkPermission
        for (ASTMethodCallExpression call : method.findDescendantsOfType(ASTMethodCallExpression.class)) {
            String m = call.getMethodName() != null ? call.getMethodName().toLowerCase() : "";
            if (m.contains("getprofile") || m.contains("getrole") || m.contains("checkperm")) {
                return true;
            }
        }
        return false;
    }
}
