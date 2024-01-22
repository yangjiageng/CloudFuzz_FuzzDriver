package fuzzing
import (
	"fmt"
	"reflect"
	admissionv1 "k8s.io/api/admission/v1"
	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	apiserverinternalv1alpha1 "k8s.io/api/apiserverinternal/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	appsv1beta1 "k8s.io/api/apps/v1beta1"
	appsv1beta2 "k8s.io/api/apps/v1beta2"
	authenticationv1 "k8s.io/api/authentication/v1"
	authenticationv1beta1 "k8s.io/api/authentication/v1beta1"
	authorizationv1 "k8s.io/api/authorization/v1"
	authorizationv1beta1 "k8s.io/api/authorization/v1beta1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	autoscalingv2beta1 "k8s.io/api/autoscaling/v2beta1"
	autoscalingv2beta2 "k8s.io/api/autoscaling/v2beta2"
	batchv1 "k8s.io/api/batch/v1"
	batchv1beta1 "k8s.io/api/batch/v1beta1"
	certificatesv1 "k8s.io/api/certificates/v1"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	coordinationv1 "k8s.io/api/coordination/v1"
	coordinationv1beta1 "k8s.io/api/coordination/v1beta1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	discoveryv1beta1 "k8s.io/api/discovery/v1beta1"
	eventsv1 "k8s.io/api/events/v1"
	eventsv1beta1 "k8s.io/api/events/v1beta1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	flowcontrolv1alpha1 "k8s.io/api/flowcontrol/v1alpha1"
	flowcontrolv1beta1 "k8s.io/api/flowcontrol/v1beta1"
	flowcontrolv1beta2 "k8s.io/api/flowcontrol/v1beta2"
	imagepolicyv1alpha1 "k8s.io/api/imagepolicy/v1alpha1"
	networkingv1 "k8s.io/api/networking/v1"
	networkingv1beta1 "k8s.io/api/networking/v1beta1"
	nodev1 "k8s.io/api/node/v1"
	nodev1alpha1 "k8s.io/api/node/v1alpha1"
	nodev1beta1 "k8s.io/api/node/v1beta1"
	policyv1 "k8s.io/api/policy/v1"
	policyv1beta1 "k8s.io/api/policy/v1beta1"
	rbacv1 "k8s.io/api/rbac/v1"
	rbacv1alpha1 "k8s.io/api/rbac/v1alpha1"
	rbacv1beta1 "k8s.io/api/rbac/v1beta1"
	schedulingv1 "k8s.io/api/scheduling/v1"
	schedulingv1alpha1 "k8s.io/api/scheduling/v1alpha1"
	schedulingv1beta1 "k8s.io/api/scheduling/v1beta1"
	storagev1 "k8s.io/api/storage/v1"
	storagev1alpha1 "k8s.io/api/storage/v1alpha1"
	storagev1beta1 "k8s.io/api/storage/v1beta1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1beta1 "k8s.io/apimachinery/pkg/apis/meta/v1beta1"
	testapigroupv1 "k8s.io/apimachinery/pkg/apis/testapigroup/v1"
	pkgruntime "k8s.io/apimachinery/pkg/runtime"
	utilintstr "k8s.io/apimachinery/pkg/util/intstr"
	auditv1 "k8s.io/apiserver/pkg/apis/audit/v1"
	runtimev1 "k8s.io/cri-api/pkg/apis/runtime/v1"
	runtimev1alpha2 "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"
	apiregistrationv1beta1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
	devicepluginv1alpha "k8s.io/kubelet/pkg/apis/deviceplugin/v1alpha"
	devicepluginv1beta1 "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
	pluginregistrationv1 "k8s.io/kubelet/pkg/apis/pluginregistration/v1"
	pluginregistrationv1alpha1 "k8s.io/kubelet/pkg/apis/pluginregistration/v1alpha1"
	pluginregistrationv1beta1 "k8s.io/kubelet/pkg/apis/pluginregistration/v1beta1"
	podresourcesv1 "k8s.io/kubelet/pkg/apis/podresources/v1"
	podresourcesv1alpha1 "k8s.io/kubelet/pkg/apis/podresources/v1alpha1"
	custom_metricsv1beta1 "k8s.io/metrics/pkg/apis/custom_metrics/v1beta1"
	custom_metricsv1beta2 "k8s.io/metrics/pkg/apis/custom_metrics/v1beta2"
	external_metricsv1beta1 "k8s.io/metrics/pkg/apis/external_metrics/v1beta1"
	metricsv1alpha1 "k8s.io/metrics/pkg/apis/metrics/v1alpha1"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"

)

const noOfTargets = 1226

func checkData(correctData1, correctData2 []byte) {
	if len(correctData1)!=len(correctData2) {
		panic("Len should be equal.")
	}
}

func FuzzApiMarshaling(data []byte) int {
	if len(data)<10 {
		return 0
	}
	op := int(data[0])
	inputData := data[1:]
		if op%noOfTargets==0 {
		fuzzadmissionv1AdmissionRequest(inputData)
	} else if op%noOfTargets==1 {
		fuzzadmissionv1AdmissionResponse(inputData)
	} else if op%noOfTargets==2 {
		fuzzadmissionv1AdmissionReview(inputData)
	} else if op%noOfTargets==3 {
		fuzzadmissionv1beta1AdmissionRequest(inputData)
	} else if op%noOfTargets==4 {
		fuzzadmissionv1beta1AdmissionResponse(inputData)
	} else if op%noOfTargets==5 {
		fuzzadmissionv1beta1AdmissionReview(inputData)
	} else if op%noOfTargets==6 {
		fuzzadmissionregistrationv1MutatingWebhook(inputData)
	} else if op%noOfTargets==7 {
		fuzzadmissionregistrationv1MutatingWebhookConfiguration(inputData)
	} else if op%noOfTargets==8 {
		fuzzadmissionregistrationv1MutatingWebhookConfigurationList(inputData)
	} else if op%noOfTargets==9 {
		fuzzadmissionregistrationv1Rule(inputData)
	} else if op%noOfTargets==10 {
		fuzzadmissionregistrationv1RuleWithOperations(inputData)
	} else if op%noOfTargets==11 {
		fuzzadmissionregistrationv1ServiceReference(inputData)
	} else if op%noOfTargets==12 {
		fuzzadmissionregistrationv1ValidatingWebhook(inputData)
	} else if op%noOfTargets==13 {
		fuzzadmissionregistrationv1ValidatingWebhookConfiguration(inputData)
	} else if op%noOfTargets==14 {
		fuzzadmissionregistrationv1ValidatingWebhookConfigurationList(inputData)
	} else if op%noOfTargets==15 {
		fuzzadmissionregistrationv1WebhookClientConfig(inputData)
	} else if op%noOfTargets==16 {
		fuzzadmissionregistrationv1beta1MutatingWebhook(inputData)
	} else if op%noOfTargets==17 {
		fuzzadmissionregistrationv1beta1MutatingWebhookConfiguration(inputData)
	} else if op%noOfTargets==18 {
		fuzzadmissionregistrationv1beta1MutatingWebhookConfigurationList(inputData)
	} else if op%noOfTargets==19 {
		fuzzadmissionregistrationv1beta1Rule(inputData)
	} else if op%noOfTargets==20 {
		fuzzadmissionregistrationv1beta1RuleWithOperations(inputData)
	} else if op%noOfTargets==21 {
		fuzzadmissionregistrationv1beta1ServiceReference(inputData)
	} else if op%noOfTargets==22 {
		fuzzadmissionregistrationv1beta1ValidatingWebhook(inputData)
	} else if op%noOfTargets==23 {
		fuzzadmissionregistrationv1beta1ValidatingWebhookConfiguration(inputData)
	} else if op%noOfTargets==24 {
		fuzzadmissionregistrationv1beta1ValidatingWebhookConfigurationList(inputData)
	} else if op%noOfTargets==25 {
		fuzzadmissionregistrationv1beta1WebhookClientConfig(inputData)
	} else if op%noOfTargets==26 {
		fuzzapiserverinternalv1alpha1ServerStorageVersion(inputData)
	} else if op%noOfTargets==27 {
		fuzzapiserverinternalv1alpha1StorageVersion(inputData)
	} else if op%noOfTargets==28 {
		fuzzapiserverinternalv1alpha1StorageVersionCondition(inputData)
	} else if op%noOfTargets==29 {
		fuzzapiserverinternalv1alpha1StorageVersionList(inputData)
	} else if op%noOfTargets==30 {
		fuzzapiserverinternalv1alpha1StorageVersionSpec(inputData)
	} else if op%noOfTargets==31 {
		fuzzapiserverinternalv1alpha1StorageVersionStatus(inputData)
	} else if op%noOfTargets==32 {
		fuzzappsv1ControllerRevision(inputData)
	} else if op%noOfTargets==33 {
		fuzzappsv1ControllerRevisionList(inputData)
	} else if op%noOfTargets==34 {
		fuzzappsv1DaemonSet(inputData)
	} else if op%noOfTargets==35 {
		fuzzappsv1DaemonSetCondition(inputData)
	} else if op%noOfTargets==36 {
		fuzzappsv1DaemonSetList(inputData)
	} else if op%noOfTargets==37 {
		fuzzappsv1DaemonSetSpec(inputData)
	} else if op%noOfTargets==38 {
		fuzzappsv1DaemonSetStatus(inputData)
	} else if op%noOfTargets==39 {
		fuzzappsv1DaemonSetUpdateStrategy(inputData)
	} else if op%noOfTargets==40 {
		fuzzappsv1Deployment(inputData)
	} else if op%noOfTargets==41 {
		fuzzappsv1DeploymentCondition(inputData)
	} else if op%noOfTargets==42 {
		fuzzappsv1DeploymentList(inputData)
	} else if op%noOfTargets==43 {
		fuzzappsv1DeploymentSpec(inputData)
	} else if op%noOfTargets==44 {
		fuzzappsv1DeploymentStatus(inputData)
	} else if op%noOfTargets==45 {
		fuzzappsv1DeploymentStrategy(inputData)
	} else if op%noOfTargets==46 {
		fuzzappsv1ReplicaSet(inputData)
	} else if op%noOfTargets==47 {
		fuzzappsv1ReplicaSetCondition(inputData)
	} else if op%noOfTargets==48 {
		fuzzappsv1ReplicaSetList(inputData)
	} else if op%noOfTargets==49 {
		fuzzappsv1ReplicaSetSpec(inputData)
	} else if op%noOfTargets==50 {
		fuzzappsv1ReplicaSetStatus(inputData)
	} else if op%noOfTargets==51 {
		fuzzappsv1RollingUpdateDaemonSet(inputData)
	} else if op%noOfTargets==52 {
		fuzzappsv1RollingUpdateDeployment(inputData)
	} else if op%noOfTargets==53 {
		fuzzappsv1RollingUpdateStatefulSetStrategy(inputData)
	} else if op%noOfTargets==54 {
		fuzzappsv1StatefulSet(inputData)
	} else if op%noOfTargets==55 {
		fuzzappsv1StatefulSetCondition(inputData)
	} else if op%noOfTargets==56 {
		fuzzappsv1StatefulSetList(inputData)
	} else if op%noOfTargets==57 {
		fuzzappsv1StatefulSetPersistentVolumeClaimRetentionPolicy(inputData)
	} else if op%noOfTargets==58 {
		fuzzappsv1StatefulSetSpec(inputData)
	} else if op%noOfTargets==59 {
		fuzzappsv1StatefulSetStatus(inputData)
	} else if op%noOfTargets==60 {
		fuzzappsv1StatefulSetUpdateStrategy(inputData)
	} else if op%noOfTargets==61 {
		fuzzappsv1beta1ControllerRevision(inputData)
	} else if op%noOfTargets==62 {
		fuzzappsv1beta1ControllerRevisionList(inputData)
	} else if op%noOfTargets==63 {
		fuzzappsv1beta1Deployment(inputData)
	} else if op%noOfTargets==64 {
		fuzzappsv1beta1DeploymentCondition(inputData)
	} else if op%noOfTargets==65 {
		fuzzappsv1beta1DeploymentList(inputData)
	} else if op%noOfTargets==66 {
		fuzzappsv1beta1DeploymentRollback(inputData)
	} else if op%noOfTargets==67 {
		fuzzappsv1beta1DeploymentSpec(inputData)
	} else if op%noOfTargets==68 {
		fuzzappsv1beta1DeploymentStatus(inputData)
	} else if op%noOfTargets==69 {
		fuzzappsv1beta1DeploymentStrategy(inputData)
	} else if op%noOfTargets==70 {
		fuzzappsv1beta1RollbackConfig(inputData)
	} else if op%noOfTargets==71 {
		fuzzappsv1beta1RollingUpdateDeployment(inputData)
	} else if op%noOfTargets==72 {
		fuzzappsv1beta1RollingUpdateStatefulSetStrategy(inputData)
	} else if op%noOfTargets==73 {
		fuzzappsv1beta1Scale(inputData)
	} else if op%noOfTargets==74 {
		fuzzappsv1beta1ScaleSpec(inputData)
	} else if op%noOfTargets==75 {
		fuzzappsv1beta1ScaleStatus(inputData)
	} else if op%noOfTargets==76 {
		fuzzappsv1beta1StatefulSet(inputData)
	} else if op%noOfTargets==77 {
		fuzzappsv1beta1StatefulSetCondition(inputData)
	} else if op%noOfTargets==78 {
		fuzzappsv1beta1StatefulSetList(inputData)
	} else if op%noOfTargets==79 {
		fuzzappsv1beta1StatefulSetPersistentVolumeClaimRetentionPolicy(inputData)
	} else if op%noOfTargets==80 {
		fuzzappsv1beta1StatefulSetSpec(inputData)
	} else if op%noOfTargets==81 {
		fuzzappsv1beta1StatefulSetStatus(inputData)
	} else if op%noOfTargets==82 {
		fuzzappsv1beta1StatefulSetUpdateStrategy(inputData)
	} else if op%noOfTargets==83 {
		fuzzappsv1beta2ControllerRevision(inputData)
	} else if op%noOfTargets==84 {
		fuzzappsv1beta2ControllerRevisionList(inputData)
	} else if op%noOfTargets==85 {
		fuzzappsv1beta2DaemonSet(inputData)
	} else if op%noOfTargets==86 {
		fuzzappsv1beta2DaemonSetCondition(inputData)
	} else if op%noOfTargets==87 {
		fuzzappsv1beta2DaemonSetList(inputData)
	} else if op%noOfTargets==88 {
		fuzzappsv1beta2DaemonSetSpec(inputData)
	} else if op%noOfTargets==89 {
		fuzzappsv1beta2DaemonSetStatus(inputData)
	} else if op%noOfTargets==90 {
		fuzzappsv1beta2DaemonSetUpdateStrategy(inputData)
	} else if op%noOfTargets==91 {
		fuzzappsv1beta2Deployment(inputData)
	} else if op%noOfTargets==92 {
		fuzzappsv1beta2DeploymentCondition(inputData)
	} else if op%noOfTargets==93 {
		fuzzappsv1beta2DeploymentList(inputData)
	} else if op%noOfTargets==94 {
		fuzzappsv1beta2DeploymentSpec(inputData)
	} else if op%noOfTargets==95 {
		fuzzappsv1beta2DeploymentStatus(inputData)
	} else if op%noOfTargets==96 {
		fuzzappsv1beta2DeploymentStrategy(inputData)
	} else if op%noOfTargets==97 {
		fuzzappsv1beta2ReplicaSet(inputData)
	} else if op%noOfTargets==98 {
		fuzzappsv1beta2ReplicaSetCondition(inputData)
	} else if op%noOfTargets==99 {
		fuzzappsv1beta2ReplicaSetList(inputData)
	} else if op%noOfTargets==100 {
		fuzzappsv1beta2ReplicaSetSpec(inputData)
	} else if op%noOfTargets==101 {
		fuzzappsv1beta2ReplicaSetStatus(inputData)
	} else if op%noOfTargets==102 {
		fuzzappsv1beta2RollingUpdateDaemonSet(inputData)
	} else if op%noOfTargets==103 {
		fuzzappsv1beta2RollingUpdateDeployment(inputData)
	} else if op%noOfTargets==104 {
		fuzzappsv1beta2RollingUpdateStatefulSetStrategy(inputData)
	} else if op%noOfTargets==105 {
		fuzzappsv1beta2Scale(inputData)
	} else if op%noOfTargets==106 {
		fuzzappsv1beta2ScaleSpec(inputData)
	} else if op%noOfTargets==107 {
		fuzzappsv1beta2ScaleStatus(inputData)
	} else if op%noOfTargets==108 {
		fuzzappsv1beta2StatefulSet(inputData)
	} else if op%noOfTargets==109 {
		fuzzappsv1beta2StatefulSetCondition(inputData)
	} else if op%noOfTargets==110 {
		fuzzappsv1beta2StatefulSetList(inputData)
	} else if op%noOfTargets==111 {
		fuzzappsv1beta2StatefulSetPersistentVolumeClaimRetentionPolicy(inputData)
	} else if op%noOfTargets==112 {
		fuzzappsv1beta2StatefulSetSpec(inputData)
	} else if op%noOfTargets==113 {
		fuzzappsv1beta2StatefulSetStatus(inputData)
	} else if op%noOfTargets==114 {
		fuzzappsv1beta2StatefulSetUpdateStrategy(inputData)
	} else if op%noOfTargets==115 {
		fuzzauthenticationv1BoundObjectReference(inputData)
	} else if op%noOfTargets==116 {
		fuzzauthenticationv1TokenRequest(inputData)
	} else if op%noOfTargets==117 {
		fuzzauthenticationv1TokenRequestSpec(inputData)
	} else if op%noOfTargets==118 {
		fuzzauthenticationv1TokenRequestStatus(inputData)
	} else if op%noOfTargets==119 {
		fuzzauthenticationv1TokenReview(inputData)
	} else if op%noOfTargets==120 {
		fuzzauthenticationv1TokenReviewSpec(inputData)
	} else if op%noOfTargets==121 {
		fuzzauthenticationv1TokenReviewStatus(inputData)
	} else if op%noOfTargets==122 {
		fuzzauthenticationv1UserInfo(inputData)
	} else if op%noOfTargets==123 {
		fuzzauthenticationv1beta1TokenReview(inputData)
	} else if op%noOfTargets==124 {
		fuzzauthenticationv1beta1TokenReviewSpec(inputData)
	} else if op%noOfTargets==125 {
		fuzzauthenticationv1beta1TokenReviewStatus(inputData)
	} else if op%noOfTargets==126 {
		fuzzauthenticationv1beta1UserInfo(inputData)
	} else if op%noOfTargets==127 {
		fuzzauthorizationv1LocalSubjectAccessReview(inputData)
	} else if op%noOfTargets==128 {
		fuzzauthorizationv1NonResourceAttributes(inputData)
	} else if op%noOfTargets==129 {
		fuzzauthorizationv1NonResourceRule(inputData)
	} else if op%noOfTargets==130 {
		fuzzauthorizationv1ResourceAttributes(inputData)
	} else if op%noOfTargets==131 {
		fuzzauthorizationv1ResourceRule(inputData)
	} else if op%noOfTargets==132 {
		fuzzauthorizationv1SelfSubjectAccessReview(inputData)
	} else if op%noOfTargets==133 {
		fuzzauthorizationv1SelfSubjectAccessReviewSpec(inputData)
	} else if op%noOfTargets==134 {
		fuzzauthorizationv1SelfSubjectRulesReview(inputData)
	} else if op%noOfTargets==135 {
		fuzzauthorizationv1SelfSubjectRulesReviewSpec(inputData)
	} else if op%noOfTargets==136 {
		fuzzauthorizationv1SubjectAccessReview(inputData)
	} else if op%noOfTargets==137 {
		fuzzauthorizationv1SubjectAccessReviewSpec(inputData)
	} else if op%noOfTargets==138 {
		fuzzauthorizationv1SubjectAccessReviewStatus(inputData)
	} else if op%noOfTargets==139 {
		fuzzauthorizationv1SubjectRulesReviewStatus(inputData)
	} else if op%noOfTargets==140 {
		fuzzauthorizationv1beta1LocalSubjectAccessReview(inputData)
	} else if op%noOfTargets==141 {
		fuzzauthorizationv1beta1NonResourceAttributes(inputData)
	} else if op%noOfTargets==142 {
		fuzzauthorizationv1beta1NonResourceRule(inputData)
	} else if op%noOfTargets==143 {
		fuzzauthorizationv1beta1ResourceAttributes(inputData)
	} else if op%noOfTargets==144 {
		fuzzauthorizationv1beta1ResourceRule(inputData)
	} else if op%noOfTargets==145 {
		fuzzauthorizationv1beta1SelfSubjectAccessReview(inputData)
	} else if op%noOfTargets==146 {
		fuzzauthorizationv1beta1SelfSubjectAccessReviewSpec(inputData)
	} else if op%noOfTargets==147 {
		fuzzauthorizationv1beta1SelfSubjectRulesReview(inputData)
	} else if op%noOfTargets==148 {
		fuzzauthorizationv1beta1SelfSubjectRulesReviewSpec(inputData)
	} else if op%noOfTargets==149 {
		fuzzauthorizationv1beta1SubjectAccessReview(inputData)
	} else if op%noOfTargets==150 {
		fuzzauthorizationv1beta1SubjectAccessReviewSpec(inputData)
	} else if op%noOfTargets==151 {
		fuzzauthorizationv1beta1SubjectAccessReviewStatus(inputData)
	} else if op%noOfTargets==152 {
		fuzzauthorizationv1beta1SubjectRulesReviewStatus(inputData)
	} else if op%noOfTargets==153 {
		fuzzautoscalingv1ContainerResourceMetricSource(inputData)
	} else if op%noOfTargets==154 {
		fuzzautoscalingv1ContainerResourceMetricStatus(inputData)
	} else if op%noOfTargets==155 {
		fuzzautoscalingv1CrossVersionObjectReference(inputData)
	} else if op%noOfTargets==156 {
		fuzzautoscalingv1ExternalMetricSource(inputData)
	} else if op%noOfTargets==157 {
		fuzzautoscalingv1ExternalMetricStatus(inputData)
	} else if op%noOfTargets==158 {
		fuzzautoscalingv1HorizontalPodAutoscaler(inputData)
	} else if op%noOfTargets==159 {
		fuzzautoscalingv1HorizontalPodAutoscalerCondition(inputData)
	} else if op%noOfTargets==160 {
		fuzzautoscalingv1HorizontalPodAutoscalerList(inputData)
	} else if op%noOfTargets==161 {
		fuzzautoscalingv1HorizontalPodAutoscalerSpec(inputData)
	} else if op%noOfTargets==162 {
		fuzzautoscalingv1HorizontalPodAutoscalerStatus(inputData)
	} else if op%noOfTargets==163 {
		fuzzautoscalingv1MetricSpec(inputData)
	} else if op%noOfTargets==164 {
		fuzzautoscalingv1MetricStatus(inputData)
	} else if op%noOfTargets==165 {
		fuzzautoscalingv1ObjectMetricSource(inputData)
	} else if op%noOfTargets==166 {
		fuzzautoscalingv1ObjectMetricStatus(inputData)
	} else if op%noOfTargets==167 {
		fuzzautoscalingv1PodsMetricSource(inputData)
	} else if op%noOfTargets==168 {
		fuzzautoscalingv1PodsMetricStatus(inputData)
	} else if op%noOfTargets==169 {
		fuzzautoscalingv1ResourceMetricSource(inputData)
	} else if op%noOfTargets==170 {
		fuzzautoscalingv1ResourceMetricStatus(inputData)
	} else if op%noOfTargets==171 {
		fuzzautoscalingv1Scale(inputData)
	} else if op%noOfTargets==172 {
		fuzzautoscalingv1ScaleSpec(inputData)
	} else if op%noOfTargets==173 {
		fuzzautoscalingv1ScaleStatus(inputData)
	} else if op%noOfTargets==174 {
		fuzzautoscalingv2ContainerResourceMetricSource(inputData)
	} else if op%noOfTargets==175 {
		fuzzautoscalingv2ContainerResourceMetricStatus(inputData)
	} else if op%noOfTargets==176 {
		fuzzautoscalingv2CrossVersionObjectReference(inputData)
	} else if op%noOfTargets==177 {
		fuzzautoscalingv2ExternalMetricSource(inputData)
	} else if op%noOfTargets==178 {
		fuzzautoscalingv2ExternalMetricStatus(inputData)
	} else if op%noOfTargets==179 {
		fuzzautoscalingv2HPAScalingPolicy(inputData)
	} else if op%noOfTargets==180 {
		fuzzautoscalingv2HPAScalingRules(inputData)
	} else if op%noOfTargets==181 {
		fuzzautoscalingv2HorizontalPodAutoscaler(inputData)
	} else if op%noOfTargets==182 {
		fuzzautoscalingv2HorizontalPodAutoscalerBehavior(inputData)
	} else if op%noOfTargets==183 {
		fuzzautoscalingv2HorizontalPodAutoscalerCondition(inputData)
	} else if op%noOfTargets==184 {
		fuzzautoscalingv2HorizontalPodAutoscalerList(inputData)
	} else if op%noOfTargets==185 {
		fuzzautoscalingv2HorizontalPodAutoscalerSpec(inputData)
	} else if op%noOfTargets==186 {
		fuzzautoscalingv2HorizontalPodAutoscalerStatus(inputData)
	} else if op%noOfTargets==187 {
		fuzzautoscalingv2MetricIdentifier(inputData)
	} else if op%noOfTargets==188 {
		fuzzautoscalingv2MetricSpec(inputData)
	} else if op%noOfTargets==189 {
		fuzzautoscalingv2MetricStatus(inputData)
	} else if op%noOfTargets==190 {
		fuzzautoscalingv2MetricTarget(inputData)
	} else if op%noOfTargets==191 {
		fuzzautoscalingv2MetricValueStatus(inputData)
	} else if op%noOfTargets==192 {
		fuzzautoscalingv2ObjectMetricSource(inputData)
	} else if op%noOfTargets==193 {
		fuzzautoscalingv2ObjectMetricStatus(inputData)
	} else if op%noOfTargets==194 {
		fuzzautoscalingv2PodsMetricSource(inputData)
	} else if op%noOfTargets==195 {
		fuzzautoscalingv2PodsMetricStatus(inputData)
	} else if op%noOfTargets==196 {
		fuzzautoscalingv2ResourceMetricSource(inputData)
	} else if op%noOfTargets==197 {
		fuzzautoscalingv2ResourceMetricStatus(inputData)
	} else if op%noOfTargets==198 {
		fuzzautoscalingv2beta1ContainerResourceMetricSource(inputData)
	} else if op%noOfTargets==199 {
		fuzzautoscalingv2beta1ContainerResourceMetricStatus(inputData)
	} else if op%noOfTargets==200 {
		fuzzautoscalingv2beta1CrossVersionObjectReference(inputData)
	} else if op%noOfTargets==201 {
		fuzzautoscalingv2beta1ExternalMetricSource(inputData)
	} else if op%noOfTargets==202 {
		fuzzautoscalingv2beta1ExternalMetricStatus(inputData)
	} else if op%noOfTargets==203 {
		fuzzautoscalingv2beta1HorizontalPodAutoscaler(inputData)
	} else if op%noOfTargets==204 {
		fuzzautoscalingv2beta1HorizontalPodAutoscalerCondition(inputData)
	} else if op%noOfTargets==205 {
		fuzzautoscalingv2beta1HorizontalPodAutoscalerList(inputData)
	} else if op%noOfTargets==206 {
		fuzzautoscalingv2beta1HorizontalPodAutoscalerSpec(inputData)
	} else if op%noOfTargets==207 {
		fuzzautoscalingv2beta1HorizontalPodAutoscalerStatus(inputData)
	} else if op%noOfTargets==208 {
		fuzzautoscalingv2beta1MetricSpec(inputData)
	} else if op%noOfTargets==209 {
		fuzzautoscalingv2beta1MetricStatus(inputData)
	} else if op%noOfTargets==210 {
		fuzzautoscalingv2beta1ObjectMetricSource(inputData)
	} else if op%noOfTargets==211 {
		fuzzautoscalingv2beta1ObjectMetricStatus(inputData)
	} else if op%noOfTargets==212 {
		fuzzautoscalingv2beta1PodsMetricSource(inputData)
	} else if op%noOfTargets==213 {
		fuzzautoscalingv2beta1PodsMetricStatus(inputData)
	} else if op%noOfTargets==214 {
		fuzzautoscalingv2beta1ResourceMetricSource(inputData)
	} else if op%noOfTargets==215 {
		fuzzautoscalingv2beta1ResourceMetricStatus(inputData)
	} else if op%noOfTargets==216 {
		fuzzautoscalingv2beta2ContainerResourceMetricSource(inputData)
	} else if op%noOfTargets==217 {
		fuzzautoscalingv2beta2ContainerResourceMetricStatus(inputData)
	} else if op%noOfTargets==218 {
		fuzzautoscalingv2beta2CrossVersionObjectReference(inputData)
	} else if op%noOfTargets==219 {
		fuzzautoscalingv2beta2ExternalMetricSource(inputData)
	} else if op%noOfTargets==220 {
		fuzzautoscalingv2beta2ExternalMetricStatus(inputData)
	} else if op%noOfTargets==221 {
		fuzzautoscalingv2beta2HPAScalingPolicy(inputData)
	} else if op%noOfTargets==222 {
		fuzzautoscalingv2beta2HPAScalingRules(inputData)
	} else if op%noOfTargets==223 {
		fuzzautoscalingv2beta2HorizontalPodAutoscaler(inputData)
	} else if op%noOfTargets==224 {
		fuzzautoscalingv2beta2HorizontalPodAutoscalerBehavior(inputData)
	} else if op%noOfTargets==225 {
		fuzzautoscalingv2beta2HorizontalPodAutoscalerCondition(inputData)
	} else if op%noOfTargets==226 {
		fuzzautoscalingv2beta2HorizontalPodAutoscalerList(inputData)
	} else if op%noOfTargets==227 {
		fuzzautoscalingv2beta2HorizontalPodAutoscalerSpec(inputData)
	} else if op%noOfTargets==228 {
		fuzzautoscalingv2beta2HorizontalPodAutoscalerStatus(inputData)
	} else if op%noOfTargets==229 {
		fuzzautoscalingv2beta2MetricIdentifier(inputData)
	} else if op%noOfTargets==230 {
		fuzzautoscalingv2beta2MetricSpec(inputData)
	} else if op%noOfTargets==231 {
		fuzzautoscalingv2beta2MetricStatus(inputData)
	} else if op%noOfTargets==232 {
		fuzzautoscalingv2beta2MetricTarget(inputData)
	} else if op%noOfTargets==233 {
		fuzzautoscalingv2beta2MetricValueStatus(inputData)
	} else if op%noOfTargets==234 {
		fuzzautoscalingv2beta2ObjectMetricSource(inputData)
	} else if op%noOfTargets==235 {
		fuzzautoscalingv2beta2ObjectMetricStatus(inputData)
	} else if op%noOfTargets==236 {
		fuzzautoscalingv2beta2PodsMetricSource(inputData)
	} else if op%noOfTargets==237 {
		fuzzautoscalingv2beta2PodsMetricStatus(inputData)
	} else if op%noOfTargets==238 {
		fuzzautoscalingv2beta2ResourceMetricSource(inputData)
	} else if op%noOfTargets==239 {
		fuzzautoscalingv2beta2ResourceMetricStatus(inputData)
	} else if op%noOfTargets==240 {
		fuzzbatchv1CronJob(inputData)
	} else if op%noOfTargets==241 {
		fuzzbatchv1CronJobList(inputData)
	} else if op%noOfTargets==242 {
		fuzzbatchv1CronJobSpec(inputData)
	} else if op%noOfTargets==243 {
		fuzzbatchv1CronJobStatus(inputData)
	} else if op%noOfTargets==244 {
		fuzzbatchv1Job(inputData)
	} else if op%noOfTargets==245 {
		fuzzbatchv1JobCondition(inputData)
	} else if op%noOfTargets==246 {
		fuzzbatchv1JobList(inputData)
	} else if op%noOfTargets==247 {
		fuzzbatchv1JobSpec(inputData)
	} else if op%noOfTargets==248 {
		fuzzbatchv1JobStatus(inputData)
	} else if op%noOfTargets==249 {
		fuzzbatchv1JobTemplateSpec(inputData)
	} else if op%noOfTargets==250 {
		fuzzbatchv1UncountedTerminatedPods(inputData)
	} else if op%noOfTargets==251 {
		fuzzbatchv1beta1CronJob(inputData)
	} else if op%noOfTargets==252 {
		fuzzbatchv1beta1CronJobList(inputData)
	} else if op%noOfTargets==253 {
		fuzzbatchv1beta1CronJobSpec(inputData)
	} else if op%noOfTargets==254 {
		fuzzbatchv1beta1CronJobStatus(inputData)
	} else if op%noOfTargets==255 {
		fuzzbatchv1beta1JobTemplate(inputData)
	} else if op%noOfTargets==256 {
		fuzzbatchv1beta1JobTemplateSpec(inputData)
	} else if op%noOfTargets==257 {
		fuzzcertificatesv1CertificateSigningRequest(inputData)
	} else if op%noOfTargets==258 {
		fuzzcertificatesv1CertificateSigningRequestCondition(inputData)
	} else if op%noOfTargets==259 {
		fuzzcertificatesv1CertificateSigningRequestList(inputData)
	} else if op%noOfTargets==260 {
		fuzzcertificatesv1CertificateSigningRequestSpec(inputData)
	} else if op%noOfTargets==261 {
		fuzzcertificatesv1CertificateSigningRequestStatus(inputData)
	} else if op%noOfTargets==262 {
		fuzzcertificatesv1beta1CertificateSigningRequest(inputData)
	} else if op%noOfTargets==263 {
		fuzzcertificatesv1beta1CertificateSigningRequestCondition(inputData)
	} else if op%noOfTargets==264 {
		fuzzcertificatesv1beta1CertificateSigningRequestList(inputData)
	} else if op%noOfTargets==265 {
		fuzzcertificatesv1beta1CertificateSigningRequestSpec(inputData)
	} else if op%noOfTargets==266 {
		fuzzcertificatesv1beta1CertificateSigningRequestStatus(inputData)
	} else if op%noOfTargets==267 {
		fuzzcoordinationv1Lease(inputData)
	} else if op%noOfTargets==268 {
		fuzzcoordinationv1LeaseList(inputData)
	} else if op%noOfTargets==269 {
		fuzzcoordinationv1LeaseSpec(inputData)
	} else if op%noOfTargets==270 {
		fuzzcoordinationv1beta1Lease(inputData)
	} else if op%noOfTargets==271 {
		fuzzcoordinationv1beta1LeaseList(inputData)
	} else if op%noOfTargets==272 {
		fuzzcoordinationv1beta1LeaseSpec(inputData)
	} else if op%noOfTargets==273 {
		fuzzcorev1AWSElasticBlockStoreVolumeSource(inputData)
	} else if op%noOfTargets==274 {
		fuzzcorev1Affinity(inputData)
	} else if op%noOfTargets==275 {
		fuzzcorev1AttachedVolume(inputData)
	} else if op%noOfTargets==276 {
		fuzzcorev1AvoidPods(inputData)
	} else if op%noOfTargets==277 {
		fuzzcorev1AzureDiskVolumeSource(inputData)
	} else if op%noOfTargets==278 {
		fuzzcorev1AzureFilePersistentVolumeSource(inputData)
	} else if op%noOfTargets==279 {
		fuzzcorev1AzureFileVolumeSource(inputData)
	} else if op%noOfTargets==280 {
		fuzzcorev1Binding(inputData)
	} else if op%noOfTargets==281 {
		fuzzcorev1CSIPersistentVolumeSource(inputData)
	} else if op%noOfTargets==282 {
		fuzzcorev1CSIVolumeSource(inputData)
	} else if op%noOfTargets==283 {
		fuzzcorev1Capabilities(inputData)
	} else if op%noOfTargets==284 {
		fuzzcorev1CephFSPersistentVolumeSource(inputData)
	} else if op%noOfTargets==285 {
		fuzzcorev1CephFSVolumeSource(inputData)
	} else if op%noOfTargets==286 {
		fuzzcorev1CinderPersistentVolumeSource(inputData)
	} else if op%noOfTargets==287 {
		fuzzcorev1CinderVolumeSource(inputData)
	} else if op%noOfTargets==288 {
		fuzzcorev1ClientIPConfig(inputData)
	} else if op%noOfTargets==289 {
		fuzzcorev1ComponentCondition(inputData)
	} else if op%noOfTargets==290 {
		fuzzcorev1ComponentStatus(inputData)
	} else if op%noOfTargets==291 {
		fuzzcorev1ComponentStatusList(inputData)
	} else if op%noOfTargets==292 {
		fuzzcorev1ConfigMap(inputData)
	} else if op%noOfTargets==293 {
		fuzzcorev1ConfigMapEnvSource(inputData)
	} else if op%noOfTargets==294 {
		fuzzcorev1ConfigMapKeySelector(inputData)
	} else if op%noOfTargets==295 {
		fuzzcorev1ConfigMapList(inputData)
	} else if op%noOfTargets==296 {
		fuzzcorev1ConfigMapNodeConfigSource(inputData)
	} else if op%noOfTargets==297 {
		fuzzcorev1ConfigMapProjection(inputData)
	} else if op%noOfTargets==298 {
		fuzzcorev1ConfigMapVolumeSource(inputData)
	} else if op%noOfTargets==299 {
		fuzzcorev1Container(inputData)
	} else if op%noOfTargets==300 {
		fuzzcorev1ContainerImage(inputData)
	} else if op%noOfTargets==301 {
		fuzzcorev1ContainerPort(inputData)
	} else if op%noOfTargets==302 {
		fuzzcorev1ContainerState(inputData)
	} else if op%noOfTargets==303 {
		fuzzcorev1ContainerStateRunning(inputData)
	} else if op%noOfTargets==304 {
		fuzzcorev1ContainerStateTerminated(inputData)
	} else if op%noOfTargets==305 {
		fuzzcorev1ContainerStateWaiting(inputData)
	} else if op%noOfTargets==306 {
		fuzzcorev1ContainerStatus(inputData)
	} else if op%noOfTargets==307 {
		fuzzcorev1DaemonEndpoint(inputData)
	} else if op%noOfTargets==308 {
		fuzzcorev1DownwardAPIProjection(inputData)
	} else if op%noOfTargets==309 {
		fuzzcorev1DownwardAPIVolumeFile(inputData)
	} else if op%noOfTargets==310 {
		fuzzcorev1DownwardAPIVolumeSource(inputData)
	} else if op%noOfTargets==311 {
		fuzzcorev1EmptyDirVolumeSource(inputData)
	} else if op%noOfTargets==312 {
		fuzzcorev1EndpointAddress(inputData)
	} else if op%noOfTargets==313 {
		fuzzcorev1EndpointPort(inputData)
	} else if op%noOfTargets==314 {
		fuzzcorev1EndpointSubset(inputData)
	} else if op%noOfTargets==315 {
		fuzzcorev1Endpoints(inputData)
	} else if op%noOfTargets==316 {
		fuzzcorev1EndpointsList(inputData)
	} else if op%noOfTargets==317 {
		fuzzcorev1EnvFromSource(inputData)
	} else if op%noOfTargets==318 {
		fuzzcorev1EnvVar(inputData)
	} else if op%noOfTargets==319 {
		fuzzcorev1EnvVarSource(inputData)
	} else if op%noOfTargets==320 {
		fuzzcorev1EphemeralContainer(inputData)
	} else if op%noOfTargets==321 {
		fuzzcorev1EphemeralContainerCommon(inputData)
	} else if op%noOfTargets==322 {
		fuzzcorev1EphemeralVolumeSource(inputData)
	} else if op%noOfTargets==323 {
		fuzzcorev1Event(inputData)
	} else if op%noOfTargets==324 {
		fuzzcorev1EventList(inputData)
	} else if op%noOfTargets==325 {
		fuzzcorev1EventSeries(inputData)
	} else if op%noOfTargets==326 {
		fuzzcorev1EventSource(inputData)
	} else if op%noOfTargets==327 {
		fuzzcorev1ExecAction(inputData)
	} else if op%noOfTargets==328 {
		fuzzcorev1FCVolumeSource(inputData)
	} else if op%noOfTargets==329 {
		fuzzcorev1FlexPersistentVolumeSource(inputData)
	} else if op%noOfTargets==330 {
		fuzzcorev1FlexVolumeSource(inputData)
	} else if op%noOfTargets==331 {
		fuzzcorev1FlockerVolumeSource(inputData)
	} else if op%noOfTargets==332 {
		fuzzcorev1GCEPersistentDiskVolumeSource(inputData)
	} else if op%noOfTargets==333 {
		fuzzcorev1GRPCAction(inputData)
	} else if op%noOfTargets==334 {
		fuzzcorev1GitRepoVolumeSource(inputData)
	} else if op%noOfTargets==335 {
		fuzzcorev1GlusterfsPersistentVolumeSource(inputData)
	} else if op%noOfTargets==336 {
		fuzzcorev1GlusterfsVolumeSource(inputData)
	} else if op%noOfTargets==337 {
		fuzzcorev1HTTPGetAction(inputData)
	} else if op%noOfTargets==338 {
		fuzzcorev1HTTPHeader(inputData)
	} else if op%noOfTargets==339 {
		fuzzcorev1HostAlias(inputData)
	} else if op%noOfTargets==340 {
		fuzzcorev1HostPathVolumeSource(inputData)
	} else if op%noOfTargets==341 {
		fuzzcorev1ISCSIPersistentVolumeSource(inputData)
	} else if op%noOfTargets==342 {
		fuzzcorev1ISCSIVolumeSource(inputData)
	} else if op%noOfTargets==343 {
		fuzzcorev1KeyToPath(inputData)
	} else if op%noOfTargets==344 {
		fuzzcorev1Lifecycle(inputData)
	} else if op%noOfTargets==345 {
		fuzzcorev1LifecycleHandler(inputData)
	} else if op%noOfTargets==346 {
		fuzzcorev1LimitRange(inputData)
	} else if op%noOfTargets==347 {
		fuzzcorev1LimitRangeItem(inputData)
	} else if op%noOfTargets==348 {
		fuzzcorev1LimitRangeList(inputData)
	} else if op%noOfTargets==349 {
		fuzzcorev1LimitRangeSpec(inputData)
	} else if op%noOfTargets==350 {
		fuzzcorev1List(inputData)
	} else if op%noOfTargets==351 {
		fuzzcorev1LoadBalancerIngress(inputData)
	} else if op%noOfTargets==352 {
		fuzzcorev1LoadBalancerStatus(inputData)
	} else if op%noOfTargets==353 {
		fuzzcorev1LocalObjectReference(inputData)
	} else if op%noOfTargets==354 {
		fuzzcorev1LocalVolumeSource(inputData)
	} else if op%noOfTargets==355 {
		fuzzcorev1NFSVolumeSource(inputData)
	} else if op%noOfTargets==356 {
		fuzzcorev1Namespace(inputData)
	} else if op%noOfTargets==357 {
		fuzzcorev1NamespaceCondition(inputData)
	} else if op%noOfTargets==358 {
		fuzzcorev1NamespaceList(inputData)
	} else if op%noOfTargets==359 {
		fuzzcorev1NamespaceSpec(inputData)
	} else if op%noOfTargets==360 {
		fuzzcorev1NamespaceStatus(inputData)
	} else if op%noOfTargets==361 {
		fuzzcorev1Node(inputData)
	} else if op%noOfTargets==362 {
		fuzzcorev1NodeAddress(inputData)
	} else if op%noOfTargets==363 {
		fuzzcorev1NodeAffinity(inputData)
	} else if op%noOfTargets==364 {
		fuzzcorev1NodeCondition(inputData)
	} else if op%noOfTargets==365 {
		fuzzcorev1NodeConfigSource(inputData)
	} else if op%noOfTargets==366 {
		fuzzcorev1NodeConfigStatus(inputData)
	} else if op%noOfTargets==367 {
		fuzzcorev1NodeDaemonEndpoints(inputData)
	} else if op%noOfTargets==368 {
		fuzzcorev1NodeList(inputData)
	} else if op%noOfTargets==369 {
		fuzzcorev1NodeProxyOptions(inputData)
	} else if op%noOfTargets==370 {
		fuzzcorev1NodeResources(inputData)
	} else if op%noOfTargets==371 {
		fuzzcorev1NodeSelector(inputData)
	} else if op%noOfTargets==372 {
		fuzzcorev1NodeSelectorRequirement(inputData)
	} else if op%noOfTargets==373 {
		fuzzcorev1NodeSelectorTerm(inputData)
	} else if op%noOfTargets==374 {
		fuzzcorev1NodeSpec(inputData)
	} else if op%noOfTargets==375 {
		fuzzcorev1NodeStatus(inputData)
	} else if op%noOfTargets==376 {
		fuzzcorev1NodeSystemInfo(inputData)
	} else if op%noOfTargets==377 {
		fuzzcorev1ObjectFieldSelector(inputData)
	} else if op%noOfTargets==378 {
		fuzzcorev1ObjectReference(inputData)
	} else if op%noOfTargets==379 {
		fuzzcorev1PersistentVolume(inputData)
	} else if op%noOfTargets==380 {
		fuzzcorev1PersistentVolumeClaim(inputData)
	} else if op%noOfTargets==381 {
		fuzzcorev1PersistentVolumeClaimCondition(inputData)
	} else if op%noOfTargets==382 {
		fuzzcorev1PersistentVolumeClaimList(inputData)
	} else if op%noOfTargets==383 {
		fuzzcorev1PersistentVolumeClaimSpec(inputData)
	} else if op%noOfTargets==384 {
		fuzzcorev1PersistentVolumeClaimStatus(inputData)
	} else if op%noOfTargets==385 {
		fuzzcorev1PersistentVolumeClaimTemplate(inputData)
	} else if op%noOfTargets==386 {
		fuzzcorev1PersistentVolumeClaimVolumeSource(inputData)
	} else if op%noOfTargets==387 {
		fuzzcorev1PersistentVolumeList(inputData)
	} else if op%noOfTargets==388 {
		fuzzcorev1PersistentVolumeSource(inputData)
	} else if op%noOfTargets==389 {
		fuzzcorev1PersistentVolumeSpec(inputData)
	} else if op%noOfTargets==390 {
		fuzzcorev1PersistentVolumeStatus(inputData)
	} else if op%noOfTargets==391 {
		fuzzcorev1PhotonPersistentDiskVolumeSource(inputData)
	} else if op%noOfTargets==392 {
		fuzzcorev1Pod(inputData)
	} else if op%noOfTargets==393 {
		fuzzcorev1PodAffinity(inputData)
	} else if op%noOfTargets==394 {
		fuzzcorev1PodAffinityTerm(inputData)
	} else if op%noOfTargets==395 {
		fuzzcorev1PodAntiAffinity(inputData)
	} else if op%noOfTargets==396 {
		fuzzcorev1PodAttachOptions(inputData)
	} else if op%noOfTargets==397 {
		fuzzcorev1PodCondition(inputData)
	} else if op%noOfTargets==398 {
		fuzzcorev1PodDNSConfig(inputData)
	} else if op%noOfTargets==399 {
		fuzzcorev1PodDNSConfigOption(inputData)
	} else if op%noOfTargets==400 {
		fuzzcorev1PodExecOptions(inputData)
	} else if op%noOfTargets==401 {
		fuzzcorev1PodIP(inputData)
	} else if op%noOfTargets==402 {
		fuzzcorev1PodList(inputData)
	} else if op%noOfTargets==403 {
		fuzzcorev1PodLogOptions(inputData)
	} else if op%noOfTargets==404 {
		fuzzcorev1PodOS(inputData)
	} else if op%noOfTargets==405 {
		fuzzcorev1PodPortForwardOptions(inputData)
	} else if op%noOfTargets==406 {
		fuzzcorev1PodProxyOptions(inputData)
	} else if op%noOfTargets==407 {
		fuzzcorev1PodReadinessGate(inputData)
	} else if op%noOfTargets==408 {
		fuzzcorev1PodSecurityContext(inputData)
	} else if op%noOfTargets==409 {
		fuzzcorev1PodSignature(inputData)
	} else if op%noOfTargets==410 {
		fuzzcorev1PodSpec(inputData)
	} else if op%noOfTargets==411 {
		fuzzcorev1PodStatus(inputData)
	} else if op%noOfTargets==412 {
		fuzzcorev1PodStatusResult(inputData)
	} else if op%noOfTargets==413 {
		fuzzcorev1PodTemplate(inputData)
	} else if op%noOfTargets==414 {
		fuzzcorev1PodTemplateList(inputData)
	} else if op%noOfTargets==415 {
		fuzzcorev1PodTemplateSpec(inputData)
	} else if op%noOfTargets==416 {
		fuzzcorev1PortStatus(inputData)
	} else if op%noOfTargets==417 {
		fuzzcorev1PortworxVolumeSource(inputData)
	} else if op%noOfTargets==418 {
		fuzzcorev1Preconditions(inputData)
	} else if op%noOfTargets==419 {
		fuzzcorev1PreferAvoidPodsEntry(inputData)
	} else if op%noOfTargets==420 {
		fuzzcorev1PreferredSchedulingTerm(inputData)
	} else if op%noOfTargets==421 {
		fuzzcorev1Probe(inputData)
	} else if op%noOfTargets==422 {
		fuzzcorev1ProbeHandler(inputData)
	} else if op%noOfTargets==423 {
		fuzzcorev1ProjectedVolumeSource(inputData)
	} else if op%noOfTargets==424 {
		fuzzcorev1QuobyteVolumeSource(inputData)
	} else if op%noOfTargets==425 {
		fuzzcorev1RBDPersistentVolumeSource(inputData)
	} else if op%noOfTargets==426 {
		fuzzcorev1RBDVolumeSource(inputData)
	} else if op%noOfTargets==427 {
		fuzzcorev1RangeAllocation(inputData)
	} else if op%noOfTargets==428 {
		fuzzcorev1ReplicationController(inputData)
	} else if op%noOfTargets==429 {
		fuzzcorev1ReplicationControllerCondition(inputData)
	} else if op%noOfTargets==430 {
		fuzzcorev1ReplicationControllerList(inputData)
	} else if op%noOfTargets==431 {
		fuzzcorev1ReplicationControllerSpec(inputData)
	} else if op%noOfTargets==432 {
		fuzzcorev1ReplicationControllerStatus(inputData)
	} else if op%noOfTargets==433 {
		fuzzcorev1ResourceFieldSelector(inputData)
	} else if op%noOfTargets==434 {
		fuzzcorev1ResourceQuota(inputData)
	} else if op%noOfTargets==435 {
		fuzzcorev1ResourceQuotaList(inputData)
	} else if op%noOfTargets==436 {
		fuzzcorev1ResourceQuotaSpec(inputData)
	} else if op%noOfTargets==437 {
		fuzzcorev1ResourceQuotaStatus(inputData)
	} else if op%noOfTargets==438 {
		fuzzcorev1ResourceRequirements(inputData)
	} else if op%noOfTargets==439 {
		fuzzcorev1SELinuxOptions(inputData)
	} else if op%noOfTargets==440 {
		fuzzcorev1ScaleIOPersistentVolumeSource(inputData)
	} else if op%noOfTargets==441 {
		fuzzcorev1ScaleIOVolumeSource(inputData)
	} else if op%noOfTargets==442 {
		fuzzcorev1ScopeSelector(inputData)
	} else if op%noOfTargets==443 {
		fuzzcorev1ScopedResourceSelectorRequirement(inputData)
	} else if op%noOfTargets==444 {
		fuzzcorev1SeccompProfile(inputData)
	} else if op%noOfTargets==445 {
		fuzzcorev1Secret(inputData)
	} else if op%noOfTargets==446 {
		fuzzcorev1SecretEnvSource(inputData)
	} else if op%noOfTargets==447 {
		fuzzcorev1SecretKeySelector(inputData)
	} else if op%noOfTargets==448 {
		fuzzcorev1SecretList(inputData)
	} else if op%noOfTargets==449 {
		fuzzcorev1SecretProjection(inputData)
	} else if op%noOfTargets==450 {
		fuzzcorev1SecretReference(inputData)
	} else if op%noOfTargets==451 {
		fuzzcorev1SecretVolumeSource(inputData)
	} else if op%noOfTargets==452 {
		fuzzcorev1SecurityContext(inputData)
	} else if op%noOfTargets==453 {
		fuzzcorev1SerializedReference(inputData)
	} else if op%noOfTargets==454 {
		fuzzcorev1Service(inputData)
	} else if op%noOfTargets==455 {
		fuzzcorev1ServiceAccount(inputData)
	} else if op%noOfTargets==456 {
		fuzzcorev1ServiceAccountList(inputData)
	} else if op%noOfTargets==457 {
		fuzzcorev1ServiceAccountTokenProjection(inputData)
	} else if op%noOfTargets==458 {
		fuzzcorev1ServiceList(inputData)
	} else if op%noOfTargets==459 {
		fuzzcorev1ServicePort(inputData)
	} else if op%noOfTargets==460 {
		fuzzcorev1ServiceProxyOptions(inputData)
	} else if op%noOfTargets==461 {
		fuzzcorev1ServiceSpec(inputData)
	} else if op%noOfTargets==462 {
		fuzzcorev1ServiceStatus(inputData)
	} else if op%noOfTargets==463 {
		fuzzcorev1SessionAffinityConfig(inputData)
	} else if op%noOfTargets==464 {
		fuzzcorev1StorageOSPersistentVolumeSource(inputData)
	} else if op%noOfTargets==465 {
		fuzzcorev1StorageOSVolumeSource(inputData)
	} else if op%noOfTargets==466 {
		fuzzcorev1Sysctl(inputData)
	} else if op%noOfTargets==467 {
		fuzzcorev1TCPSocketAction(inputData)
	} else if op%noOfTargets==468 {
		fuzzcorev1Taint(inputData)
	} else if op%noOfTargets==469 {
		fuzzcorev1Toleration(inputData)
	} else if op%noOfTargets==470 {
		fuzzcorev1TopologySelectorLabelRequirement(inputData)
	} else if op%noOfTargets==471 {
		fuzzcorev1TopologySelectorTerm(inputData)
	} else if op%noOfTargets==472 {
		fuzzcorev1TopologySpreadConstraint(inputData)
	} else if op%noOfTargets==473 {
		fuzzcorev1TypedLocalObjectReference(inputData)
	} else if op%noOfTargets==474 {
		fuzzcorev1Volume(inputData)
	} else if op%noOfTargets==475 {
		fuzzcorev1VolumeDevice(inputData)
	} else if op%noOfTargets==476 {
		fuzzcorev1VolumeMount(inputData)
	} else if op%noOfTargets==477 {
		fuzzcorev1VolumeNodeAffinity(inputData)
	} else if op%noOfTargets==478 {
		fuzzcorev1VolumeProjection(inputData)
	} else if op%noOfTargets==479 {
		fuzzcorev1VolumeSource(inputData)
	} else if op%noOfTargets==480 {
		fuzzcorev1VsphereVirtualDiskVolumeSource(inputData)
	} else if op%noOfTargets==481 {
		fuzzcorev1WeightedPodAffinityTerm(inputData)
	} else if op%noOfTargets==482 {
		fuzzcorev1WindowsSecurityContextOptions(inputData)
	} else if op%noOfTargets==483 {
		fuzzdiscoveryv1Endpoint(inputData)
	} else if op%noOfTargets==484 {
		fuzzdiscoveryv1EndpointConditions(inputData)
	} else if op%noOfTargets==485 {
		fuzzdiscoveryv1EndpointHints(inputData)
	} else if op%noOfTargets==486 {
		fuzzdiscoveryv1EndpointPort(inputData)
	} else if op%noOfTargets==487 {
		fuzzdiscoveryv1EndpointSlice(inputData)
	} else if op%noOfTargets==488 {
		fuzzdiscoveryv1EndpointSliceList(inputData)
	} else if op%noOfTargets==489 {
		fuzzdiscoveryv1ForZone(inputData)
	} else if op%noOfTargets==490 {
		fuzzdiscoveryv1beta1Endpoint(inputData)
	} else if op%noOfTargets==491 {
		fuzzdiscoveryv1beta1EndpointConditions(inputData)
	} else if op%noOfTargets==492 {
		fuzzdiscoveryv1beta1EndpointHints(inputData)
	} else if op%noOfTargets==493 {
		fuzzdiscoveryv1beta1EndpointPort(inputData)
	} else if op%noOfTargets==494 {
		fuzzdiscoveryv1beta1EndpointSlice(inputData)
	} else if op%noOfTargets==495 {
		fuzzdiscoveryv1beta1EndpointSliceList(inputData)
	} else if op%noOfTargets==496 {
		fuzzdiscoveryv1beta1ForZone(inputData)
	} else if op%noOfTargets==497 {
		fuzzeventsv1Event(inputData)
	} else if op%noOfTargets==498 {
		fuzzeventsv1EventList(inputData)
	} else if op%noOfTargets==499 {
		fuzzeventsv1EventSeries(inputData)
	} else if op%noOfTargets==500 {
		fuzzeventsv1beta1Event(inputData)
	} else if op%noOfTargets==501 {
		fuzzeventsv1beta1EventList(inputData)
	} else if op%noOfTargets==502 {
		fuzzeventsv1beta1EventSeries(inputData)
	} else if op%noOfTargets==503 {
		fuzzextensionsv1beta1AllowedCSIDriver(inputData)
	} else if op%noOfTargets==504 {
		fuzzextensionsv1beta1AllowedFlexVolume(inputData)
	} else if op%noOfTargets==505 {
		fuzzextensionsv1beta1AllowedHostPath(inputData)
	} else if op%noOfTargets==506 {
		fuzzextensionsv1beta1DaemonSet(inputData)
	} else if op%noOfTargets==507 {
		fuzzextensionsv1beta1DaemonSetCondition(inputData)
	} else if op%noOfTargets==508 {
		fuzzextensionsv1beta1DaemonSetList(inputData)
	} else if op%noOfTargets==509 {
		fuzzextensionsv1beta1DaemonSetSpec(inputData)
	} else if op%noOfTargets==510 {
		fuzzextensionsv1beta1DaemonSetStatus(inputData)
	} else if op%noOfTargets==511 {
		fuzzextensionsv1beta1DaemonSetUpdateStrategy(inputData)
	} else if op%noOfTargets==512 {
		fuzzextensionsv1beta1Deployment(inputData)
	} else if op%noOfTargets==513 {
		fuzzextensionsv1beta1DeploymentCondition(inputData)
	} else if op%noOfTargets==514 {
		fuzzextensionsv1beta1DeploymentList(inputData)
	} else if op%noOfTargets==515 {
		fuzzextensionsv1beta1DeploymentRollback(inputData)
	} else if op%noOfTargets==516 {
		fuzzextensionsv1beta1DeploymentSpec(inputData)
	} else if op%noOfTargets==517 {
		fuzzextensionsv1beta1DeploymentStatus(inputData)
	} else if op%noOfTargets==518 {
		fuzzextensionsv1beta1DeploymentStrategy(inputData)
	} else if op%noOfTargets==519 {
		fuzzextensionsv1beta1FSGroupStrategyOptions(inputData)
	} else if op%noOfTargets==520 {
		fuzzextensionsv1beta1HTTPIngressPath(inputData)
	} else if op%noOfTargets==521 {
		fuzzextensionsv1beta1HTTPIngressRuleValue(inputData)
	} else if op%noOfTargets==522 {
		fuzzextensionsv1beta1HostPortRange(inputData)
	} else if op%noOfTargets==523 {
		fuzzextensionsv1beta1IDRange(inputData)
	} else if op%noOfTargets==524 {
		fuzzextensionsv1beta1IPBlock(inputData)
	} else if op%noOfTargets==525 {
		fuzzextensionsv1beta1Ingress(inputData)
	} else if op%noOfTargets==526 {
		fuzzextensionsv1beta1IngressBackend(inputData)
	} else if op%noOfTargets==527 {
		fuzzextensionsv1beta1IngressList(inputData)
	} else if op%noOfTargets==528 {
		fuzzextensionsv1beta1IngressRule(inputData)
	} else if op%noOfTargets==529 {
		fuzzextensionsv1beta1IngressRuleValue(inputData)
	} else if op%noOfTargets==530 {
		fuzzextensionsv1beta1IngressSpec(inputData)
	} else if op%noOfTargets==531 {
		fuzzextensionsv1beta1IngressStatus(inputData)
	} else if op%noOfTargets==532 {
		fuzzextensionsv1beta1IngressTLS(inputData)
	} else if op%noOfTargets==533 {
		fuzzextensionsv1beta1NetworkPolicy(inputData)
	} else if op%noOfTargets==534 {
		fuzzextensionsv1beta1NetworkPolicyEgressRule(inputData)
	} else if op%noOfTargets==535 {
		fuzzextensionsv1beta1NetworkPolicyIngressRule(inputData)
	} else if op%noOfTargets==536 {
		fuzzextensionsv1beta1NetworkPolicyList(inputData)
	} else if op%noOfTargets==537 {
		fuzzextensionsv1beta1NetworkPolicyPeer(inputData)
	} else if op%noOfTargets==538 {
		fuzzextensionsv1beta1NetworkPolicyPort(inputData)
	} else if op%noOfTargets==539 {
		fuzzextensionsv1beta1NetworkPolicySpec(inputData)
	} else if op%noOfTargets==540 {
		fuzzextensionsv1beta1NetworkPolicyStatus(inputData)
	} else if op%noOfTargets==541 {
		fuzzextensionsv1beta1PodSecurityPolicy(inputData)
	} else if op%noOfTargets==542 {
		fuzzextensionsv1beta1PodSecurityPolicyList(inputData)
	} else if op%noOfTargets==543 {
		fuzzextensionsv1beta1PodSecurityPolicySpec(inputData)
	} else if op%noOfTargets==544 {
		fuzzextensionsv1beta1ReplicaSet(inputData)
	} else if op%noOfTargets==545 {
		fuzzextensionsv1beta1ReplicaSetCondition(inputData)
	} else if op%noOfTargets==546 {
		fuzzextensionsv1beta1ReplicaSetList(inputData)
	} else if op%noOfTargets==547 {
		fuzzextensionsv1beta1ReplicaSetSpec(inputData)
	} else if op%noOfTargets==548 {
		fuzzextensionsv1beta1ReplicaSetStatus(inputData)
	} else if op%noOfTargets==549 {
		fuzzextensionsv1beta1RollbackConfig(inputData)
	} else if op%noOfTargets==550 {
		fuzzextensionsv1beta1RollingUpdateDaemonSet(inputData)
	} else if op%noOfTargets==551 {
		fuzzextensionsv1beta1RollingUpdateDeployment(inputData)
	} else if op%noOfTargets==552 {
		fuzzextensionsv1beta1RunAsGroupStrategyOptions(inputData)
	} else if op%noOfTargets==553 {
		fuzzextensionsv1beta1RunAsUserStrategyOptions(inputData)
	} else if op%noOfTargets==554 {
		fuzzextensionsv1beta1RuntimeClassStrategyOptions(inputData)
	} else if op%noOfTargets==555 {
		fuzzextensionsv1beta1SELinuxStrategyOptions(inputData)
	} else if op%noOfTargets==556 {
		fuzzextensionsv1beta1Scale(inputData)
	} else if op%noOfTargets==557 {
		fuzzextensionsv1beta1ScaleSpec(inputData)
	} else if op%noOfTargets==558 {
		fuzzextensionsv1beta1ScaleStatus(inputData)
	} else if op%noOfTargets==559 {
		fuzzextensionsv1beta1SupplementalGroupsStrategyOptions(inputData)
	} else if op%noOfTargets==560 {
		fuzzflowcontrolv1alpha1FlowDistinguisherMethod(inputData)
	} else if op%noOfTargets==561 {
		fuzzflowcontrolv1alpha1FlowSchema(inputData)
	} else if op%noOfTargets==562 {
		fuzzflowcontrolv1alpha1FlowSchemaCondition(inputData)
	} else if op%noOfTargets==563 {
		fuzzflowcontrolv1alpha1FlowSchemaList(inputData)
	} else if op%noOfTargets==564 {
		fuzzflowcontrolv1alpha1FlowSchemaSpec(inputData)
	} else if op%noOfTargets==565 {
		fuzzflowcontrolv1alpha1FlowSchemaStatus(inputData)
	} else if op%noOfTargets==566 {
		fuzzflowcontrolv1alpha1GroupSubject(inputData)
	} else if op%noOfTargets==567 {
		fuzzflowcontrolv1alpha1LimitResponse(inputData)
	} else if op%noOfTargets==568 {
		fuzzflowcontrolv1alpha1LimitedPriorityLevelConfiguration(inputData)
	} else if op%noOfTargets==569 {
		fuzzflowcontrolv1alpha1NonResourcePolicyRule(inputData)
	} else if op%noOfTargets==570 {
		fuzzflowcontrolv1alpha1PolicyRulesWithSubjects(inputData)
	} else if op%noOfTargets==571 {
		fuzzflowcontrolv1alpha1PriorityLevelConfiguration(inputData)
	} else if op%noOfTargets==572 {
		fuzzflowcontrolv1alpha1PriorityLevelConfigurationCondition(inputData)
	} else if op%noOfTargets==573 {
		fuzzflowcontrolv1alpha1PriorityLevelConfigurationList(inputData)
	} else if op%noOfTargets==574 {
		fuzzflowcontrolv1alpha1PriorityLevelConfigurationReference(inputData)
	} else if op%noOfTargets==575 {
		fuzzflowcontrolv1alpha1PriorityLevelConfigurationSpec(inputData)
	} else if op%noOfTargets==576 {
		fuzzflowcontrolv1alpha1PriorityLevelConfigurationStatus(inputData)
	} else if op%noOfTargets==577 {
		fuzzflowcontrolv1alpha1QueuingConfiguration(inputData)
	} else if op%noOfTargets==578 {
		fuzzflowcontrolv1alpha1ResourcePolicyRule(inputData)
	} else if op%noOfTargets==579 {
		fuzzflowcontrolv1alpha1ServiceAccountSubject(inputData)
	} else if op%noOfTargets==580 {
		fuzzflowcontrolv1alpha1Subject(inputData)
	} else if op%noOfTargets==581 {
		fuzzflowcontrolv1alpha1UserSubject(inputData)
	} else if op%noOfTargets==582 {
		fuzzflowcontrolv1beta1FlowDistinguisherMethod(inputData)
	} else if op%noOfTargets==583 {
		fuzzflowcontrolv1beta1FlowSchema(inputData)
	} else if op%noOfTargets==584 {
		fuzzflowcontrolv1beta1FlowSchemaCondition(inputData)
	} else if op%noOfTargets==585 {
		fuzzflowcontrolv1beta1FlowSchemaList(inputData)
	} else if op%noOfTargets==586 {
		fuzzflowcontrolv1beta1FlowSchemaSpec(inputData)
	} else if op%noOfTargets==587 {
		fuzzflowcontrolv1beta1FlowSchemaStatus(inputData)
	} else if op%noOfTargets==588 {
		fuzzflowcontrolv1beta1GroupSubject(inputData)
	} else if op%noOfTargets==589 {
		fuzzflowcontrolv1beta1LimitResponse(inputData)
	} else if op%noOfTargets==590 {
		fuzzflowcontrolv1beta1LimitedPriorityLevelConfiguration(inputData)
	} else if op%noOfTargets==591 {
		fuzzflowcontrolv1beta1NonResourcePolicyRule(inputData)
	} else if op%noOfTargets==592 {
		fuzzflowcontrolv1beta1PolicyRulesWithSubjects(inputData)
	} else if op%noOfTargets==593 {
		fuzzflowcontrolv1beta1PriorityLevelConfiguration(inputData)
	} else if op%noOfTargets==594 {
		fuzzflowcontrolv1beta1PriorityLevelConfigurationCondition(inputData)
	} else if op%noOfTargets==595 {
		fuzzflowcontrolv1beta1PriorityLevelConfigurationList(inputData)
	} else if op%noOfTargets==596 {
		fuzzflowcontrolv1beta1PriorityLevelConfigurationReference(inputData)
	} else if op%noOfTargets==597 {
		fuzzflowcontrolv1beta1PriorityLevelConfigurationSpec(inputData)
	} else if op%noOfTargets==598 {
		fuzzflowcontrolv1beta1PriorityLevelConfigurationStatus(inputData)
	} else if op%noOfTargets==599 {
		fuzzflowcontrolv1beta1QueuingConfiguration(inputData)
	} else if op%noOfTargets==600 {
		fuzzflowcontrolv1beta1ResourcePolicyRule(inputData)
	} else if op%noOfTargets==601 {
		fuzzflowcontrolv1beta1ServiceAccountSubject(inputData)
	} else if op%noOfTargets==602 {
		fuzzflowcontrolv1beta1Subject(inputData)
	} else if op%noOfTargets==603 {
		fuzzflowcontrolv1beta1UserSubject(inputData)
	} else if op%noOfTargets==604 {
		fuzzflowcontrolv1beta2FlowDistinguisherMethod(inputData)
	} else if op%noOfTargets==605 {
		fuzzflowcontrolv1beta2FlowSchema(inputData)
	} else if op%noOfTargets==606 {
		fuzzflowcontrolv1beta2FlowSchemaCondition(inputData)
	} else if op%noOfTargets==607 {
		fuzzflowcontrolv1beta2FlowSchemaList(inputData)
	} else if op%noOfTargets==608 {
		fuzzflowcontrolv1beta2FlowSchemaSpec(inputData)
	} else if op%noOfTargets==609 {
		fuzzflowcontrolv1beta2FlowSchemaStatus(inputData)
	} else if op%noOfTargets==610 {
		fuzzflowcontrolv1beta2GroupSubject(inputData)
	} else if op%noOfTargets==611 {
		fuzzflowcontrolv1beta2LimitResponse(inputData)
	} else if op%noOfTargets==612 {
		fuzzflowcontrolv1beta2LimitedPriorityLevelConfiguration(inputData)
	} else if op%noOfTargets==613 {
		fuzzflowcontrolv1beta2NonResourcePolicyRule(inputData)
	} else if op%noOfTargets==614 {
		fuzzflowcontrolv1beta2PolicyRulesWithSubjects(inputData)
	} else if op%noOfTargets==615 {
		fuzzflowcontrolv1beta2PriorityLevelConfiguration(inputData)
	} else if op%noOfTargets==616 {
		fuzzflowcontrolv1beta2PriorityLevelConfigurationCondition(inputData)
	} else if op%noOfTargets==617 {
		fuzzflowcontrolv1beta2PriorityLevelConfigurationList(inputData)
	} else if op%noOfTargets==618 {
		fuzzflowcontrolv1beta2PriorityLevelConfigurationReference(inputData)
	} else if op%noOfTargets==619 {
		fuzzflowcontrolv1beta2PriorityLevelConfigurationSpec(inputData)
	} else if op%noOfTargets==620 {
		fuzzflowcontrolv1beta2PriorityLevelConfigurationStatus(inputData)
	} else if op%noOfTargets==621 {
		fuzzflowcontrolv1beta2QueuingConfiguration(inputData)
	} else if op%noOfTargets==622 {
		fuzzflowcontrolv1beta2ResourcePolicyRule(inputData)
	} else if op%noOfTargets==623 {
		fuzzflowcontrolv1beta2ServiceAccountSubject(inputData)
	} else if op%noOfTargets==624 {
		fuzzflowcontrolv1beta2Subject(inputData)
	} else if op%noOfTargets==625 {
		fuzzflowcontrolv1beta2UserSubject(inputData)
	} else if op%noOfTargets==626 {
		fuzzimagepolicyv1alpha1ImageReview(inputData)
	} else if op%noOfTargets==627 {
		fuzzimagepolicyv1alpha1ImageReviewContainerSpec(inputData)
	} else if op%noOfTargets==628 {
		fuzzimagepolicyv1alpha1ImageReviewSpec(inputData)
	} else if op%noOfTargets==629 {
		fuzzimagepolicyv1alpha1ImageReviewStatus(inputData)
	} else if op%noOfTargets==630 {
		fuzznetworkingv1HTTPIngressPath(inputData)
	} else if op%noOfTargets==631 {
		fuzznetworkingv1HTTPIngressRuleValue(inputData)
	} else if op%noOfTargets==632 {
		fuzznetworkingv1IPBlock(inputData)
	} else if op%noOfTargets==633 {
		fuzznetworkingv1Ingress(inputData)
	} else if op%noOfTargets==634 {
		fuzznetworkingv1IngressBackend(inputData)
	} else if op%noOfTargets==635 {
		fuzznetworkingv1IngressClass(inputData)
	} else if op%noOfTargets==636 {
		fuzznetworkingv1IngressClassList(inputData)
	} else if op%noOfTargets==637 {
		fuzznetworkingv1IngressClassParametersReference(inputData)
	} else if op%noOfTargets==638 {
		fuzznetworkingv1IngressClassSpec(inputData)
	} else if op%noOfTargets==639 {
		fuzznetworkingv1IngressList(inputData)
	} else if op%noOfTargets==640 {
		fuzznetworkingv1IngressRule(inputData)
	} else if op%noOfTargets==641 {
		fuzznetworkingv1IngressRuleValue(inputData)
	} else if op%noOfTargets==642 {
		fuzznetworkingv1IngressServiceBackend(inputData)
	} else if op%noOfTargets==643 {
		fuzznetworkingv1IngressSpec(inputData)
	} else if op%noOfTargets==644 {
		fuzznetworkingv1IngressStatus(inputData)
	} else if op%noOfTargets==645 {
		fuzznetworkingv1IngressTLS(inputData)
	} else if op%noOfTargets==646 {
		fuzznetworkingv1NetworkPolicy(inputData)
	} else if op%noOfTargets==647 {
		fuzznetworkingv1NetworkPolicyEgressRule(inputData)
	} else if op%noOfTargets==648 {
		fuzznetworkingv1NetworkPolicyIngressRule(inputData)
	} else if op%noOfTargets==649 {
		fuzznetworkingv1NetworkPolicyList(inputData)
	} else if op%noOfTargets==650 {
		fuzznetworkingv1NetworkPolicyPeer(inputData)
	} else if op%noOfTargets==651 {
		fuzznetworkingv1NetworkPolicyPort(inputData)
	} else if op%noOfTargets==652 {
		fuzznetworkingv1NetworkPolicySpec(inputData)
	} else if op%noOfTargets==653 {
		fuzznetworkingv1NetworkPolicyStatus(inputData)
	} else if op%noOfTargets==654 {
		fuzznetworkingv1ServiceBackendPort(inputData)
	} else if op%noOfTargets==655 {
		fuzznetworkingv1beta1HTTPIngressPath(inputData)
	} else if op%noOfTargets==656 {
		fuzznetworkingv1beta1HTTPIngressRuleValue(inputData)
	} else if op%noOfTargets==657 {
		fuzznetworkingv1beta1Ingress(inputData)
	} else if op%noOfTargets==658 {
		fuzznetworkingv1beta1IngressBackend(inputData)
	} else if op%noOfTargets==659 {
		fuzznetworkingv1beta1IngressClass(inputData)
	} else if op%noOfTargets==660 {
		fuzznetworkingv1beta1IngressClassList(inputData)
	} else if op%noOfTargets==661 {
		fuzznetworkingv1beta1IngressClassParametersReference(inputData)
	} else if op%noOfTargets==662 {
		fuzznetworkingv1beta1IngressClassSpec(inputData)
	} else if op%noOfTargets==663 {
		fuzznetworkingv1beta1IngressList(inputData)
	} else if op%noOfTargets==664 {
		fuzznetworkingv1beta1IngressRule(inputData)
	} else if op%noOfTargets==665 {
		fuzznetworkingv1beta1IngressRuleValue(inputData)
	} else if op%noOfTargets==666 {
		fuzznetworkingv1beta1IngressSpec(inputData)
	} else if op%noOfTargets==667 {
		fuzznetworkingv1beta1IngressStatus(inputData)
	} else if op%noOfTargets==668 {
		fuzznetworkingv1beta1IngressTLS(inputData)
	} else if op%noOfTargets==669 {
		fuzznodev1Overhead(inputData)
	} else if op%noOfTargets==670 {
		fuzznodev1RuntimeClass(inputData)
	} else if op%noOfTargets==671 {
		fuzznodev1RuntimeClassList(inputData)
	} else if op%noOfTargets==672 {
		fuzznodev1Scheduling(inputData)
	} else if op%noOfTargets==673 {
		fuzznodev1alpha1Overhead(inputData)
	} else if op%noOfTargets==674 {
		fuzznodev1alpha1RuntimeClass(inputData)
	} else if op%noOfTargets==675 {
		fuzznodev1alpha1RuntimeClassList(inputData)
	} else if op%noOfTargets==676 {
		fuzznodev1alpha1RuntimeClassSpec(inputData)
	} else if op%noOfTargets==677 {
		fuzznodev1alpha1Scheduling(inputData)
	} else if op%noOfTargets==678 {
		fuzznodev1beta1Overhead(inputData)
	} else if op%noOfTargets==679 {
		fuzznodev1beta1RuntimeClass(inputData)
	} else if op%noOfTargets==680 {
		fuzznodev1beta1RuntimeClassList(inputData)
	} else if op%noOfTargets==681 {
		fuzznodev1beta1Scheduling(inputData)
	} else if op%noOfTargets==682 {
		fuzzpolicyv1Eviction(inputData)
	} else if op%noOfTargets==683 {
		fuzzpolicyv1PodDisruptionBudget(inputData)
	} else if op%noOfTargets==684 {
		fuzzpolicyv1PodDisruptionBudgetList(inputData)
	} else if op%noOfTargets==685 {
		fuzzpolicyv1PodDisruptionBudgetSpec(inputData)
	} else if op%noOfTargets==686 {
		fuzzpolicyv1PodDisruptionBudgetStatus(inputData)
	} else if op%noOfTargets==687 {
		fuzzpolicyv1beta1AllowedCSIDriver(inputData)
	} else if op%noOfTargets==688 {
		fuzzpolicyv1beta1AllowedFlexVolume(inputData)
	} else if op%noOfTargets==689 {
		fuzzpolicyv1beta1AllowedHostPath(inputData)
	} else if op%noOfTargets==690 {
		fuzzpolicyv1beta1Eviction(inputData)
	} else if op%noOfTargets==691 {
		fuzzpolicyv1beta1FSGroupStrategyOptions(inputData)
	} else if op%noOfTargets==692 {
		fuzzpolicyv1beta1HostPortRange(inputData)
	} else if op%noOfTargets==693 {
		fuzzpolicyv1beta1IDRange(inputData)
	} else if op%noOfTargets==694 {
		fuzzpolicyv1beta1PodDisruptionBudget(inputData)
	} else if op%noOfTargets==695 {
		fuzzpolicyv1beta1PodDisruptionBudgetList(inputData)
	} else if op%noOfTargets==696 {
		fuzzpolicyv1beta1PodDisruptionBudgetSpec(inputData)
	} else if op%noOfTargets==697 {
		fuzzpolicyv1beta1PodDisruptionBudgetStatus(inputData)
	} else if op%noOfTargets==698 {
		fuzzpolicyv1beta1PodSecurityPolicy(inputData)
	} else if op%noOfTargets==699 {
		fuzzpolicyv1beta1PodSecurityPolicyList(inputData)
	} else if op%noOfTargets==700 {
		fuzzpolicyv1beta1PodSecurityPolicySpec(inputData)
	} else if op%noOfTargets==701 {
		fuzzpolicyv1beta1RunAsGroupStrategyOptions(inputData)
	} else if op%noOfTargets==702 {
		fuzzpolicyv1beta1RunAsUserStrategyOptions(inputData)
	} else if op%noOfTargets==703 {
		fuzzpolicyv1beta1RuntimeClassStrategyOptions(inputData)
	} else if op%noOfTargets==704 {
		fuzzpolicyv1beta1SELinuxStrategyOptions(inputData)
	} else if op%noOfTargets==705 {
		fuzzpolicyv1beta1SupplementalGroupsStrategyOptions(inputData)
	} else if op%noOfTargets==706 {
		fuzzrbacv1AggregationRule(inputData)
	} else if op%noOfTargets==707 {
		fuzzrbacv1ClusterRole(inputData)
	} else if op%noOfTargets==708 {
		fuzzrbacv1ClusterRoleBinding(inputData)
	} else if op%noOfTargets==709 {
		fuzzrbacv1ClusterRoleBindingList(inputData)
	} else if op%noOfTargets==710 {
		fuzzrbacv1ClusterRoleList(inputData)
	} else if op%noOfTargets==711 {
		fuzzrbacv1PolicyRule(inputData)
	} else if op%noOfTargets==712 {
		fuzzrbacv1Role(inputData)
	} else if op%noOfTargets==713 {
		fuzzrbacv1RoleBinding(inputData)
	} else if op%noOfTargets==714 {
		fuzzrbacv1RoleBindingList(inputData)
	} else if op%noOfTargets==715 {
		fuzzrbacv1RoleList(inputData)
	} else if op%noOfTargets==716 {
		fuzzrbacv1RoleRef(inputData)
	} else if op%noOfTargets==717 {
		fuzzrbacv1Subject(inputData)
	} else if op%noOfTargets==718 {
		fuzzrbacv1alpha1AggregationRule(inputData)
	} else if op%noOfTargets==719 {
		fuzzrbacv1alpha1ClusterRole(inputData)
	} else if op%noOfTargets==720 {
		fuzzrbacv1alpha1ClusterRoleBinding(inputData)
	} else if op%noOfTargets==721 {
		fuzzrbacv1alpha1ClusterRoleBindingList(inputData)
	} else if op%noOfTargets==722 {
		fuzzrbacv1alpha1ClusterRoleList(inputData)
	} else if op%noOfTargets==723 {
		fuzzrbacv1alpha1PolicyRule(inputData)
	} else if op%noOfTargets==724 {
		fuzzrbacv1alpha1Role(inputData)
	} else if op%noOfTargets==725 {
		fuzzrbacv1alpha1RoleBinding(inputData)
	} else if op%noOfTargets==726 {
		fuzzrbacv1alpha1RoleBindingList(inputData)
	} else if op%noOfTargets==727 {
		fuzzrbacv1alpha1RoleList(inputData)
	} else if op%noOfTargets==728 {
		fuzzrbacv1alpha1RoleRef(inputData)
	} else if op%noOfTargets==729 {
		fuzzrbacv1alpha1Subject(inputData)
	} else if op%noOfTargets==730 {
		fuzzrbacv1beta1AggregationRule(inputData)
	} else if op%noOfTargets==731 {
		fuzzrbacv1beta1ClusterRole(inputData)
	} else if op%noOfTargets==732 {
		fuzzrbacv1beta1ClusterRoleBinding(inputData)
	} else if op%noOfTargets==733 {
		fuzzrbacv1beta1ClusterRoleBindingList(inputData)
	} else if op%noOfTargets==734 {
		fuzzrbacv1beta1ClusterRoleList(inputData)
	} else if op%noOfTargets==735 {
		fuzzrbacv1beta1PolicyRule(inputData)
	} else if op%noOfTargets==736 {
		fuzzrbacv1beta1Role(inputData)
	} else if op%noOfTargets==737 {
		fuzzrbacv1beta1RoleBinding(inputData)
	} else if op%noOfTargets==738 {
		fuzzrbacv1beta1RoleBindingList(inputData)
	} else if op%noOfTargets==739 {
		fuzzrbacv1beta1RoleList(inputData)
	} else if op%noOfTargets==740 {
		fuzzrbacv1beta1RoleRef(inputData)
	} else if op%noOfTargets==741 {
		fuzzrbacv1beta1Subject(inputData)
	} else if op%noOfTargets==742 {
		fuzzschedulingv1PriorityClass(inputData)
	} else if op%noOfTargets==743 {
		fuzzschedulingv1PriorityClassList(inputData)
	} else if op%noOfTargets==744 {
		fuzzschedulingv1alpha1PriorityClass(inputData)
	} else if op%noOfTargets==745 {
		fuzzschedulingv1alpha1PriorityClassList(inputData)
	} else if op%noOfTargets==746 {
		fuzzschedulingv1beta1PriorityClass(inputData)
	} else if op%noOfTargets==747 {
		fuzzschedulingv1beta1PriorityClassList(inputData)
	} else if op%noOfTargets==748 {
		fuzzstoragev1CSIDriver(inputData)
	} else if op%noOfTargets==749 {
		fuzzstoragev1CSIDriverList(inputData)
	} else if op%noOfTargets==750 {
		fuzzstoragev1CSIDriverSpec(inputData)
	} else if op%noOfTargets==751 {
		fuzzstoragev1CSINode(inputData)
	} else if op%noOfTargets==752 {
		fuzzstoragev1CSINodeDriver(inputData)
	} else if op%noOfTargets==753 {
		fuzzstoragev1CSINodeList(inputData)
	} else if op%noOfTargets==754 {
		fuzzstoragev1CSINodeSpec(inputData)
	} else if op%noOfTargets==755 {
		fuzzstoragev1CSIStorageCapacity(inputData)
	} else if op%noOfTargets==756 {
		fuzzstoragev1CSIStorageCapacityList(inputData)
	} else if op%noOfTargets==757 {
		fuzzstoragev1StorageClass(inputData)
	} else if op%noOfTargets==758 {
		fuzzstoragev1StorageClassList(inputData)
	} else if op%noOfTargets==759 {
		fuzzstoragev1TokenRequest(inputData)
	} else if op%noOfTargets==760 {
		fuzzstoragev1VolumeAttachment(inputData)
	} else if op%noOfTargets==761 {
		fuzzstoragev1VolumeAttachmentList(inputData)
	} else if op%noOfTargets==762 {
		fuzzstoragev1VolumeAttachmentSource(inputData)
	} else if op%noOfTargets==763 {
		fuzzstoragev1VolumeAttachmentSpec(inputData)
	} else if op%noOfTargets==764 {
		fuzzstoragev1VolumeAttachmentStatus(inputData)
	} else if op%noOfTargets==765 {
		fuzzstoragev1VolumeError(inputData)
	} else if op%noOfTargets==766 {
		fuzzstoragev1VolumeNodeResources(inputData)
	} else if op%noOfTargets==767 {
		fuzzstoragev1alpha1CSIStorageCapacity(inputData)
	} else if op%noOfTargets==768 {
		fuzzstoragev1alpha1CSIStorageCapacityList(inputData)
	} else if op%noOfTargets==769 {
		fuzzstoragev1alpha1VolumeAttachment(inputData)
	} else if op%noOfTargets==770 {
		fuzzstoragev1alpha1VolumeAttachmentList(inputData)
	} else if op%noOfTargets==771 {
		fuzzstoragev1alpha1VolumeAttachmentSource(inputData)
	} else if op%noOfTargets==772 {
		fuzzstoragev1alpha1VolumeAttachmentSpec(inputData)
	} else if op%noOfTargets==773 {
		fuzzstoragev1alpha1VolumeAttachmentStatus(inputData)
	} else if op%noOfTargets==774 {
		fuzzstoragev1alpha1VolumeError(inputData)
	} else if op%noOfTargets==775 {
		fuzzstoragev1beta1CSIDriver(inputData)
	} else if op%noOfTargets==776 {
		fuzzstoragev1beta1CSIDriverList(inputData)
	} else if op%noOfTargets==777 {
		fuzzstoragev1beta1CSIDriverSpec(inputData)
	} else if op%noOfTargets==778 {
		fuzzstoragev1beta1CSINode(inputData)
	} else if op%noOfTargets==779 {
		fuzzstoragev1beta1CSINodeDriver(inputData)
	} else if op%noOfTargets==780 {
		fuzzstoragev1beta1CSINodeList(inputData)
	} else if op%noOfTargets==781 {
		fuzzstoragev1beta1CSINodeSpec(inputData)
	} else if op%noOfTargets==782 {
		fuzzstoragev1beta1CSIStorageCapacity(inputData)
	} else if op%noOfTargets==783 {
		fuzzstoragev1beta1CSIStorageCapacityList(inputData)
	} else if op%noOfTargets==784 {
		fuzzstoragev1beta1StorageClass(inputData)
	} else if op%noOfTargets==785 {
		fuzzstoragev1beta1StorageClassList(inputData)
	} else if op%noOfTargets==786 {
		fuzzstoragev1beta1TokenRequest(inputData)
	} else if op%noOfTargets==787 {
		fuzzstoragev1beta1VolumeAttachment(inputData)
	} else if op%noOfTargets==788 {
		fuzzstoragev1beta1VolumeAttachmentList(inputData)
	} else if op%noOfTargets==789 {
		fuzzstoragev1beta1VolumeAttachmentSource(inputData)
	} else if op%noOfTargets==790 {
		fuzzstoragev1beta1VolumeAttachmentSpec(inputData)
	} else if op%noOfTargets==791 {
		fuzzstoragev1beta1VolumeAttachmentStatus(inputData)
	} else if op%noOfTargets==792 {
		fuzzstoragev1beta1VolumeError(inputData)
	} else if op%noOfTargets==793 {
		fuzzstoragev1beta1VolumeNodeResources(inputData)
	} else if op%noOfTargets==794 {
		fuzzapiextensionsv1ConversionRequest(inputData)
	} else if op%noOfTargets==795 {
		fuzzapiextensionsv1ConversionResponse(inputData)
	} else if op%noOfTargets==796 {
		fuzzapiextensionsv1ConversionReview(inputData)
	} else if op%noOfTargets==797 {
		fuzzapiextensionsv1CustomResourceColumnDefinition(inputData)
	} else if op%noOfTargets==798 {
		fuzzapiextensionsv1CustomResourceConversion(inputData)
	} else if op%noOfTargets==799 {
		fuzzapiextensionsv1CustomResourceDefinition(inputData)
	} else if op%noOfTargets==800 {
		fuzzapiextensionsv1CustomResourceDefinitionCondition(inputData)
	} else if op%noOfTargets==801 {
		fuzzapiextensionsv1CustomResourceDefinitionList(inputData)
	} else if op%noOfTargets==802 {
		fuzzapiextensionsv1CustomResourceDefinitionNames(inputData)
	} else if op%noOfTargets==803 {
		fuzzapiextensionsv1CustomResourceDefinitionSpec(inputData)
	} else if op%noOfTargets==804 {
		fuzzapiextensionsv1CustomResourceDefinitionStatus(inputData)
	} else if op%noOfTargets==805 {
		fuzzapiextensionsv1CustomResourceDefinitionVersion(inputData)
	} else if op%noOfTargets==806 {
		fuzzapiextensionsv1CustomResourceSubresourceScale(inputData)
	} else if op%noOfTargets==807 {
		fuzzapiextensionsv1CustomResourceSubresourceStatus(inputData)
	} else if op%noOfTargets==808 {
		fuzzapiextensionsv1CustomResourceSubresources(inputData)
	} else if op%noOfTargets==809 {
		fuzzapiextensionsv1CustomResourceValidation(inputData)
	} else if op%noOfTargets==810 {
		fuzzapiextensionsv1ExternalDocumentation(inputData)
	} else if op%noOfTargets==811 {
		fuzzapiextensionsv1JSON(inputData)
	} else if op%noOfTargets==812 {
		fuzzapiextensionsv1JSONSchemaProps(inputData)
	} else if op%noOfTargets==813 {
		fuzzapiextensionsv1JSONSchemaPropsOrArray(inputData)
	} else if op%noOfTargets==814 {
		fuzzapiextensionsv1JSONSchemaPropsOrBool(inputData)
	} else if op%noOfTargets==815 {
		fuzzapiextensionsv1JSONSchemaPropsOrStringArray(inputData)
	} else if op%noOfTargets==816 {
		fuzzapiextensionsv1ServiceReference(inputData)
	} else if op%noOfTargets==817 {
		fuzzapiextensionsv1ValidationRule(inputData)
	} else if op%noOfTargets==818 {
		fuzzapiextensionsv1WebhookClientConfig(inputData)
	} else if op%noOfTargets==819 {
		fuzzapiextensionsv1WebhookConversion(inputData)
	} else if op%noOfTargets==820 {
		fuzzapiextensionsv1beta1ConversionRequest(inputData)
	} else if op%noOfTargets==821 {
		fuzzapiextensionsv1beta1ConversionResponse(inputData)
	} else if op%noOfTargets==822 {
		fuzzapiextensionsv1beta1ConversionReview(inputData)
	} else if op%noOfTargets==823 {
		fuzzapiextensionsv1beta1CustomResourceColumnDefinition(inputData)
	} else if op%noOfTargets==824 {
		fuzzapiextensionsv1beta1CustomResourceConversion(inputData)
	} else if op%noOfTargets==825 {
		fuzzapiextensionsv1beta1CustomResourceDefinition(inputData)
	} else if op%noOfTargets==826 {
		fuzzapiextensionsv1beta1CustomResourceDefinitionCondition(inputData)
	} else if op%noOfTargets==827 {
		fuzzapiextensionsv1beta1CustomResourceDefinitionList(inputData)
	} else if op%noOfTargets==828 {
		fuzzapiextensionsv1beta1CustomResourceDefinitionNames(inputData)
	} else if op%noOfTargets==829 {
		fuzzapiextensionsv1beta1CustomResourceDefinitionSpec(inputData)
	} else if op%noOfTargets==830 {
		fuzzapiextensionsv1beta1CustomResourceDefinitionStatus(inputData)
	} else if op%noOfTargets==831 {
		fuzzapiextensionsv1beta1CustomResourceDefinitionVersion(inputData)
	} else if op%noOfTargets==832 {
		fuzzapiextensionsv1beta1CustomResourceSubresourceScale(inputData)
	} else if op%noOfTargets==833 {
		fuzzapiextensionsv1beta1CustomResourceSubresourceStatus(inputData)
	} else if op%noOfTargets==834 {
		fuzzapiextensionsv1beta1CustomResourceSubresources(inputData)
	} else if op%noOfTargets==835 {
		fuzzapiextensionsv1beta1CustomResourceValidation(inputData)
	} else if op%noOfTargets==836 {
		fuzzapiextensionsv1beta1ExternalDocumentation(inputData)
	} else if op%noOfTargets==837 {
		fuzzapiextensionsv1beta1JSON(inputData)
	} else if op%noOfTargets==838 {
		fuzzapiextensionsv1beta1JSONSchemaProps(inputData)
	} else if op%noOfTargets==839 {
		fuzzapiextensionsv1beta1JSONSchemaPropsOrArray(inputData)
	} else if op%noOfTargets==840 {
		fuzzapiextensionsv1beta1JSONSchemaPropsOrBool(inputData)
	} else if op%noOfTargets==841 {
		fuzzapiextensionsv1beta1JSONSchemaPropsOrStringArray(inputData)
	} else if op%noOfTargets==842 {
		fuzzapiextensionsv1beta1ServiceReference(inputData)
	} else if op%noOfTargets==843 {
		fuzzapiextensionsv1beta1ValidationRule(inputData)
	} else if op%noOfTargets==844 {
		fuzzapiextensionsv1beta1WebhookClientConfig(inputData)
	} else if op%noOfTargets==845 {
		fuzzmetav1APIGroup(inputData)
	} else if op%noOfTargets==846 {
		fuzzmetav1APIGroupList(inputData)
	} else if op%noOfTargets==847 {
		fuzzmetav1APIResource(inputData)
	} else if op%noOfTargets==848 {
		fuzzmetav1APIResourceList(inputData)
	} else if op%noOfTargets==849 {
		fuzzmetav1APIVersions(inputData)
	} else if op%noOfTargets==850 {
		fuzzmetav1ApplyOptions(inputData)
	} else if op%noOfTargets==851 {
		fuzzmetav1Condition(inputData)
	} else if op%noOfTargets==852 {
		fuzzmetav1CreateOptions(inputData)
	} else if op%noOfTargets==853 {
		fuzzmetav1DeleteOptions(inputData)
	} else if op%noOfTargets==854 {
		fuzzmetav1Duration(inputData)
	} else if op%noOfTargets==855 {
		fuzzmetav1FieldsV1(inputData)
	} else if op%noOfTargets==856 {
		fuzzmetav1GetOptions(inputData)
	} else if op%noOfTargets==857 {
		fuzzmetav1GroupKind(inputData)
	} else if op%noOfTargets==858 {
		fuzzmetav1GroupResource(inputData)
	} else if op%noOfTargets==859 {
		fuzzmetav1GroupVersion(inputData)
	} else if op%noOfTargets==860 {
		fuzzmetav1GroupVersionForDiscovery(inputData)
	} else if op%noOfTargets==861 {
		fuzzmetav1GroupVersionKind(inputData)
	} else if op%noOfTargets==862 {
		fuzzmetav1GroupVersionResource(inputData)
	} else if op%noOfTargets==863 {
		fuzzmetav1LabelSelector(inputData)
	} else if op%noOfTargets==864 {
		fuzzmetav1LabelSelectorRequirement(inputData)
	} else if op%noOfTargets==865 {
		fuzzmetav1List(inputData)
	} else if op%noOfTargets==866 {
		fuzzmetav1ListMeta(inputData)
	} else if op%noOfTargets==867 {
		fuzzmetav1ListOptions(inputData)
	} else if op%noOfTargets==868 {
		fuzzmetav1ManagedFieldsEntry(inputData)
	} else if op%noOfTargets==869 {
		fuzzmetav1ObjectMeta(inputData)
	} else if op%noOfTargets==870 {
		fuzzmetav1OwnerReference(inputData)
	} else if op%noOfTargets==871 {
		fuzzmetav1PartialObjectMetadata(inputData)
	} else if op%noOfTargets==872 {
		fuzzmetav1PartialObjectMetadataList(inputData)
	} else if op%noOfTargets==873 {
		fuzzmetav1Patch(inputData)
	} else if op%noOfTargets==874 {
		fuzzmetav1PatchOptions(inputData)
	} else if op%noOfTargets==875 {
		fuzzmetav1Preconditions(inputData)
	} else if op%noOfTargets==876 {
		fuzzmetav1RootPaths(inputData)
	} else if op%noOfTargets==877 {
		fuzzmetav1ServerAddressByClientCIDR(inputData)
	} else if op%noOfTargets==878 {
		fuzzmetav1Status(inputData)
	} else if op%noOfTargets==879 {
		fuzzmetav1StatusCause(inputData)
	} else if op%noOfTargets==880 {
		fuzzmetav1StatusDetails(inputData)
	} else if op%noOfTargets==881 {
		fuzzmetav1TableOptions(inputData)
	} else if op%noOfTargets==882 {
		fuzzmetav1Timestamp(inputData)
	} else if op%noOfTargets==883 {
		fuzzmetav1TypeMeta(inputData)
	} else if op%noOfTargets==884 {
		fuzzmetav1UpdateOptions(inputData)
	} else if op%noOfTargets==885 {
		fuzzmetav1WatchEvent(inputData)
	} else if op%noOfTargets==886 {
		fuzzmetav1beta1PartialObjectMetadataList(inputData)
	} else if op%noOfTargets==887 {
		fuzztestapigroupv1Carp(inputData)
	} else if op%noOfTargets==888 {
		fuzztestapigroupv1CarpCondition(inputData)
	} else if op%noOfTargets==889 {
		fuzztestapigroupv1CarpList(inputData)
	} else if op%noOfTargets==890 {
		fuzztestapigroupv1CarpSpec(inputData)
	} else if op%noOfTargets==891 {
		fuzztestapigroupv1CarpStatus(inputData)
	} else if op%noOfTargets==892 {
		fuzzpkgruntimeRawExtension(inputData)
	} else if op%noOfTargets==893 {
		fuzzpkgruntimeTypeMeta(inputData)
	} else if op%noOfTargets==894 {
		fuzzpkgruntimeUnknown(inputData)
	} else if op%noOfTargets==895 {
		fuzzutilintstrIntOrString(inputData)
	} else if op%noOfTargets==896 {
		fuzzauditv1Event(inputData)
	} else if op%noOfTargets==897 {
		fuzzauditv1EventList(inputData)
	} else if op%noOfTargets==898 {
		fuzzauditv1GroupResources(inputData)
	} else if op%noOfTargets==899 {
		fuzzauditv1ObjectReference(inputData)
	} else if op%noOfTargets==900 {
		fuzzauditv1Policy(inputData)
	} else if op%noOfTargets==901 {
		fuzzauditv1PolicyList(inputData)
	} else if op%noOfTargets==902 {
		fuzzauditv1PolicyRule(inputData)
	} else if op%noOfTargets==903 {
		fuzzruntimev1VersionRequest(inputData)
	} else if op%noOfTargets==904 {
		fuzzruntimev1VersionResponse(inputData)
	} else if op%noOfTargets==905 {
		fuzzruntimev1DNSConfig(inputData)
	} else if op%noOfTargets==906 {
		fuzzruntimev1PortMapping(inputData)
	} else if op%noOfTargets==907 {
		fuzzruntimev1Mount(inputData)
	} else if op%noOfTargets==908 {
		fuzzruntimev1NamespaceOption(inputData)
	} else if op%noOfTargets==909 {
		fuzzruntimev1Int64Value(inputData)
	} else if op%noOfTargets==910 {
		fuzzruntimev1LinuxSandboxSecurityContext(inputData)
	} else if op%noOfTargets==911 {
		fuzzruntimev1SecurityProfile(inputData)
	} else if op%noOfTargets==912 {
		fuzzruntimev1LinuxPodSandboxConfig(inputData)
	} else if op%noOfTargets==913 {
		fuzzruntimev1PodSandboxMetadata(inputData)
	} else if op%noOfTargets==914 {
		fuzzruntimev1PodSandboxConfig(inputData)
	} else if op%noOfTargets==915 {
		fuzzruntimev1RunPodSandboxRequest(inputData)
	} else if op%noOfTargets==916 {
		fuzzruntimev1RunPodSandboxResponse(inputData)
	} else if op%noOfTargets==917 {
		fuzzruntimev1StopPodSandboxRequest(inputData)
	} else if op%noOfTargets==918 {
		fuzzruntimev1StopPodSandboxResponse(inputData)
	} else if op%noOfTargets==919 {
		fuzzruntimev1RemovePodSandboxRequest(inputData)
	} else if op%noOfTargets==920 {
		fuzzruntimev1RemovePodSandboxResponse(inputData)
	} else if op%noOfTargets==921 {
		fuzzruntimev1PodSandboxStatusRequest(inputData)
	} else if op%noOfTargets==922 {
		fuzzruntimev1PodIP(inputData)
	} else if op%noOfTargets==923 {
		fuzzruntimev1PodSandboxNetworkStatus(inputData)
	} else if op%noOfTargets==924 {
		fuzzruntimev1Namespace(inputData)
	} else if op%noOfTargets==925 {
		fuzzruntimev1LinuxPodSandboxStatus(inputData)
	} else if op%noOfTargets==926 {
		fuzzruntimev1PodSandboxStatus(inputData)
	} else if op%noOfTargets==927 {
		fuzzruntimev1PodSandboxStatusResponse(inputData)
	} else if op%noOfTargets==928 {
		fuzzruntimev1PodSandboxStateValue(inputData)
	} else if op%noOfTargets==929 {
		fuzzruntimev1PodSandboxFilter(inputData)
	} else if op%noOfTargets==930 {
		fuzzruntimev1ListPodSandboxRequest(inputData)
	} else if op%noOfTargets==931 {
		fuzzruntimev1PodSandbox(inputData)
	} else if op%noOfTargets==932 {
		fuzzruntimev1ListPodSandboxResponse(inputData)
	} else if op%noOfTargets==933 {
		fuzzruntimev1PodSandboxStatsRequest(inputData)
	} else if op%noOfTargets==934 {
		fuzzruntimev1PodSandboxStatsResponse(inputData)
	} else if op%noOfTargets==935 {
		fuzzruntimev1PodSandboxStatsFilter(inputData)
	} else if op%noOfTargets==936 {
		fuzzruntimev1ListPodSandboxStatsRequest(inputData)
	} else if op%noOfTargets==937 {
		fuzzruntimev1ListPodSandboxStatsResponse(inputData)
	} else if op%noOfTargets==938 {
		fuzzruntimev1PodSandboxAttributes(inputData)
	} else if op%noOfTargets==939 {
		fuzzruntimev1PodSandboxStats(inputData)
	} else if op%noOfTargets==940 {
		fuzzruntimev1LinuxPodSandboxStats(inputData)
	} else if op%noOfTargets==941 {
		fuzzruntimev1WindowsPodSandboxStats(inputData)
	} else if op%noOfTargets==942 {
		fuzzruntimev1NetworkUsage(inputData)
	} else if op%noOfTargets==943 {
		fuzzruntimev1NetworkInterfaceUsage(inputData)
	} else if op%noOfTargets==944 {
		fuzzruntimev1ProcessUsage(inputData)
	} else if op%noOfTargets==945 {
		fuzzruntimev1ImageSpec(inputData)
	} else if op%noOfTargets==946 {
		fuzzruntimev1KeyValue(inputData)
	} else if op%noOfTargets==947 {
		fuzzruntimev1LinuxContainerResources(inputData)
	} else if op%noOfTargets==948 {
		fuzzruntimev1HugepageLimit(inputData)
	} else if op%noOfTargets==949 {
		fuzzruntimev1SELinuxOption(inputData)
	} else if op%noOfTargets==950 {
		fuzzruntimev1Capability(inputData)
	} else if op%noOfTargets==951 {
		fuzzruntimev1LinuxContainerSecurityContext(inputData)
	} else if op%noOfTargets==952 {
		fuzzruntimev1LinuxContainerConfig(inputData)
	} else if op%noOfTargets==953 {
		fuzzruntimev1WindowsSandboxSecurityContext(inputData)
	} else if op%noOfTargets==954 {
		fuzzruntimev1WindowsPodSandboxConfig(inputData)
	} else if op%noOfTargets==955 {
		fuzzruntimev1WindowsContainerSecurityContext(inputData)
	} else if op%noOfTargets==956 {
		fuzzruntimev1WindowsContainerConfig(inputData)
	} else if op%noOfTargets==957 {
		fuzzruntimev1WindowsContainerResources(inputData)
	} else if op%noOfTargets==958 {
		fuzzruntimev1ContainerMetadata(inputData)
	} else if op%noOfTargets==959 {
		fuzzruntimev1Device(inputData)
	} else if op%noOfTargets==960 {
		fuzzruntimev1ContainerConfig(inputData)
	} else if op%noOfTargets==961 {
		fuzzruntimev1CreateContainerRequest(inputData)
	} else if op%noOfTargets==962 {
		fuzzruntimev1CreateContainerResponse(inputData)
	} else if op%noOfTargets==963 {
		fuzzruntimev1StartContainerRequest(inputData)
	} else if op%noOfTargets==964 {
		fuzzruntimev1StartContainerResponse(inputData)
	} else if op%noOfTargets==965 {
		fuzzruntimev1StopContainerRequest(inputData)
	} else if op%noOfTargets==966 {
		fuzzruntimev1StopContainerResponse(inputData)
	} else if op%noOfTargets==967 {
		fuzzruntimev1RemoveContainerRequest(inputData)
	} else if op%noOfTargets==968 {
		fuzzruntimev1RemoveContainerResponse(inputData)
	} else if op%noOfTargets==969 {
		fuzzruntimev1ContainerStateValue(inputData)
	} else if op%noOfTargets==970 {
		fuzzruntimev1ContainerFilter(inputData)
	} else if op%noOfTargets==971 {
		fuzzruntimev1ListContainersRequest(inputData)
	} else if op%noOfTargets==972 {
		fuzzruntimev1Container(inputData)
	} else if op%noOfTargets==973 {
		fuzzruntimev1ListContainersResponse(inputData)
	} else if op%noOfTargets==974 {
		fuzzruntimev1ContainerStatusRequest(inputData)
	} else if op%noOfTargets==975 {
		fuzzruntimev1ContainerStatus(inputData)
	} else if op%noOfTargets==976 {
		fuzzruntimev1ContainerStatusResponse(inputData)
	} else if op%noOfTargets==977 {
		fuzzruntimev1UpdateContainerResourcesRequest(inputData)
	} else if op%noOfTargets==978 {
		fuzzruntimev1UpdateContainerResourcesResponse(inputData)
	} else if op%noOfTargets==979 {
		fuzzruntimev1ExecSyncRequest(inputData)
	} else if op%noOfTargets==980 {
		fuzzruntimev1ExecSyncResponse(inputData)
	} else if op%noOfTargets==981 {
		fuzzruntimev1ExecRequest(inputData)
	} else if op%noOfTargets==982 {
		fuzzruntimev1ExecResponse(inputData)
	} else if op%noOfTargets==983 {
		fuzzruntimev1AttachRequest(inputData)
	} else if op%noOfTargets==984 {
		fuzzruntimev1AttachResponse(inputData)
	} else if op%noOfTargets==985 {
		fuzzruntimev1PortForwardRequest(inputData)
	} else if op%noOfTargets==986 {
		fuzzruntimev1PortForwardResponse(inputData)
	} else if op%noOfTargets==987 {
		fuzzruntimev1ImageFilter(inputData)
	} else if op%noOfTargets==988 {
		fuzzruntimev1ListImagesRequest(inputData)
	} else if op%noOfTargets==989 {
		fuzzruntimev1Image(inputData)
	} else if op%noOfTargets==990 {
		fuzzruntimev1ListImagesResponse(inputData)
	} else if op%noOfTargets==991 {
		fuzzruntimev1ImageStatusRequest(inputData)
	} else if op%noOfTargets==992 {
		fuzzruntimev1ImageStatusResponse(inputData)
	} else if op%noOfTargets==993 {
		fuzzruntimev1AuthConfig(inputData)
	} else if op%noOfTargets==994 {
		fuzzruntimev1PullImageRequest(inputData)
	} else if op%noOfTargets==995 {
		fuzzruntimev1PullImageResponse(inputData)
	} else if op%noOfTargets==996 {
		fuzzruntimev1RemoveImageRequest(inputData)
	} else if op%noOfTargets==997 {
		fuzzruntimev1RemoveImageResponse(inputData)
	} else if op%noOfTargets==998 {
		fuzzruntimev1NetworkConfig(inputData)
	} else if op%noOfTargets==999 {
		fuzzruntimev1RuntimeConfig(inputData)
	} else if op%noOfTargets==1000 {
		fuzzruntimev1UpdateRuntimeConfigRequest(inputData)
	} else if op%noOfTargets==1001 {
		fuzzruntimev1UpdateRuntimeConfigResponse(inputData)
	} else if op%noOfTargets==1002 {
		fuzzruntimev1RuntimeCondition(inputData)
	} else if op%noOfTargets==1003 {
		fuzzruntimev1RuntimeStatus(inputData)
	} else if op%noOfTargets==1004 {
		fuzzruntimev1StatusRequest(inputData)
	} else if op%noOfTargets==1005 {
		fuzzruntimev1StatusResponse(inputData)
	} else if op%noOfTargets==1006 {
		fuzzruntimev1ImageFsInfoRequest(inputData)
	} else if op%noOfTargets==1007 {
		fuzzruntimev1UInt64Value(inputData)
	} else if op%noOfTargets==1008 {
		fuzzruntimev1FilesystemIdentifier(inputData)
	} else if op%noOfTargets==1009 {
		fuzzruntimev1FilesystemUsage(inputData)
	} else if op%noOfTargets==1010 {
		fuzzruntimev1ImageFsInfoResponse(inputData)
	} else if op%noOfTargets==1011 {
		fuzzruntimev1ContainerStatsRequest(inputData)
	} else if op%noOfTargets==1012 {
		fuzzruntimev1ContainerStatsResponse(inputData)
	} else if op%noOfTargets==1013 {
		fuzzruntimev1ListContainerStatsRequest(inputData)
	} else if op%noOfTargets==1014 {
		fuzzruntimev1ContainerStatsFilter(inputData)
	} else if op%noOfTargets==1015 {
		fuzzruntimev1ListContainerStatsResponse(inputData)
	} else if op%noOfTargets==1016 {
		fuzzruntimev1ContainerAttributes(inputData)
	} else if op%noOfTargets==1017 {
		fuzzruntimev1ContainerStats(inputData)
	} else if op%noOfTargets==1018 {
		fuzzruntimev1CpuUsage(inputData)
	} else if op%noOfTargets==1019 {
		fuzzruntimev1MemoryUsage(inputData)
	} else if op%noOfTargets==1020 {
		fuzzruntimev1ReopenContainerLogRequest(inputData)
	} else if op%noOfTargets==1021 {
		fuzzruntimev1ReopenContainerLogResponse(inputData)
	} else if op%noOfTargets==1022 {
		fuzzruntimev1alpha2VersionRequest(inputData)
	} else if op%noOfTargets==1023 {
		fuzzruntimev1alpha2VersionResponse(inputData)
	} else if op%noOfTargets==1024 {
		fuzzruntimev1alpha2DNSConfig(inputData)
	} else if op%noOfTargets==1025 {
		fuzzruntimev1alpha2PortMapping(inputData)
	} else if op%noOfTargets==1026 {
		fuzzruntimev1alpha2Mount(inputData)
	} else if op%noOfTargets==1027 {
		fuzzruntimev1alpha2NamespaceOption(inputData)
	} else if op%noOfTargets==1028 {
		fuzzruntimev1alpha2Int64Value(inputData)
	} else if op%noOfTargets==1029 {
		fuzzruntimev1alpha2LinuxSandboxSecurityContext(inputData)
	} else if op%noOfTargets==1030 {
		fuzzruntimev1alpha2SecurityProfile(inputData)
	} else if op%noOfTargets==1031 {
		fuzzruntimev1alpha2LinuxPodSandboxConfig(inputData)
	} else if op%noOfTargets==1032 {
		fuzzruntimev1alpha2PodSandboxMetadata(inputData)
	} else if op%noOfTargets==1033 {
		fuzzruntimev1alpha2PodSandboxConfig(inputData)
	} else if op%noOfTargets==1034 {
		fuzzruntimev1alpha2RunPodSandboxRequest(inputData)
	} else if op%noOfTargets==1035 {
		fuzzruntimev1alpha2RunPodSandboxResponse(inputData)
	} else if op%noOfTargets==1036 {
		fuzzruntimev1alpha2StopPodSandboxRequest(inputData)
	} else if op%noOfTargets==1037 {
		fuzzruntimev1alpha2StopPodSandboxResponse(inputData)
	} else if op%noOfTargets==1038 {
		fuzzruntimev1alpha2RemovePodSandboxRequest(inputData)
	} else if op%noOfTargets==1039 {
		fuzzruntimev1alpha2RemovePodSandboxResponse(inputData)
	} else if op%noOfTargets==1040 {
		fuzzruntimev1alpha2PodSandboxStatusRequest(inputData)
	} else if op%noOfTargets==1041 {
		fuzzruntimev1alpha2PodIP(inputData)
	} else if op%noOfTargets==1042 {
		fuzzruntimev1alpha2PodSandboxNetworkStatus(inputData)
	} else if op%noOfTargets==1043 {
		fuzzruntimev1alpha2Namespace(inputData)
	} else if op%noOfTargets==1044 {
		fuzzruntimev1alpha2LinuxPodSandboxStatus(inputData)
	} else if op%noOfTargets==1045 {
		fuzzruntimev1alpha2PodSandboxStatus(inputData)
	} else if op%noOfTargets==1046 {
		fuzzruntimev1alpha2PodSandboxStatusResponse(inputData)
	} else if op%noOfTargets==1047 {
		fuzzruntimev1alpha2PodSandboxStateValue(inputData)
	} else if op%noOfTargets==1048 {
		fuzzruntimev1alpha2PodSandboxFilter(inputData)
	} else if op%noOfTargets==1049 {
		fuzzruntimev1alpha2ListPodSandboxRequest(inputData)
	} else if op%noOfTargets==1050 {
		fuzzruntimev1alpha2PodSandbox(inputData)
	} else if op%noOfTargets==1051 {
		fuzzruntimev1alpha2ListPodSandboxResponse(inputData)
	} else if op%noOfTargets==1052 {
		fuzzruntimev1alpha2PodSandboxStatsRequest(inputData)
	} else if op%noOfTargets==1053 {
		fuzzruntimev1alpha2PodSandboxStatsResponse(inputData)
	} else if op%noOfTargets==1054 {
		fuzzruntimev1alpha2PodSandboxStatsFilter(inputData)
	} else if op%noOfTargets==1055 {
		fuzzruntimev1alpha2ListPodSandboxStatsRequest(inputData)
	} else if op%noOfTargets==1056 {
		fuzzruntimev1alpha2ListPodSandboxStatsResponse(inputData)
	} else if op%noOfTargets==1057 {
		fuzzruntimev1alpha2PodSandboxAttributes(inputData)
	} else if op%noOfTargets==1058 {
		fuzzruntimev1alpha2PodSandboxStats(inputData)
	} else if op%noOfTargets==1059 {
		fuzzruntimev1alpha2LinuxPodSandboxStats(inputData)
	} else if op%noOfTargets==1060 {
		fuzzruntimev1alpha2WindowsPodSandboxStats(inputData)
	} else if op%noOfTargets==1061 {
		fuzzruntimev1alpha2NetworkUsage(inputData)
	} else if op%noOfTargets==1062 {
		fuzzruntimev1alpha2NetworkInterfaceUsage(inputData)
	} else if op%noOfTargets==1063 {
		fuzzruntimev1alpha2ProcessUsage(inputData)
	} else if op%noOfTargets==1064 {
		fuzzruntimev1alpha2ImageSpec(inputData)
	} else if op%noOfTargets==1065 {
		fuzzruntimev1alpha2KeyValue(inputData)
	} else if op%noOfTargets==1066 {
		fuzzruntimev1alpha2LinuxContainerResources(inputData)
	} else if op%noOfTargets==1067 {
		fuzzruntimev1alpha2HugepageLimit(inputData)
	} else if op%noOfTargets==1068 {
		fuzzruntimev1alpha2SELinuxOption(inputData)
	} else if op%noOfTargets==1069 {
		fuzzruntimev1alpha2Capability(inputData)
	} else if op%noOfTargets==1070 {
		fuzzruntimev1alpha2LinuxContainerSecurityContext(inputData)
	} else if op%noOfTargets==1071 {
		fuzzruntimev1alpha2LinuxContainerConfig(inputData)
	} else if op%noOfTargets==1072 {
		fuzzruntimev1alpha2WindowsSandboxSecurityContext(inputData)
	} else if op%noOfTargets==1073 {
		fuzzruntimev1alpha2WindowsPodSandboxConfig(inputData)
	} else if op%noOfTargets==1074 {
		fuzzruntimev1alpha2WindowsContainerSecurityContext(inputData)
	} else if op%noOfTargets==1075 {
		fuzzruntimev1alpha2WindowsContainerConfig(inputData)
	} else if op%noOfTargets==1076 {
		fuzzruntimev1alpha2WindowsContainerResources(inputData)
	} else if op%noOfTargets==1077 {
		fuzzruntimev1alpha2ContainerMetadata(inputData)
	} else if op%noOfTargets==1078 {
		fuzzruntimev1alpha2Device(inputData)
	} else if op%noOfTargets==1079 {
		fuzzruntimev1alpha2ContainerConfig(inputData)
	} else if op%noOfTargets==1080 {
		fuzzruntimev1alpha2CreateContainerRequest(inputData)
	} else if op%noOfTargets==1081 {
		fuzzruntimev1alpha2CreateContainerResponse(inputData)
	} else if op%noOfTargets==1082 {
		fuzzruntimev1alpha2StartContainerRequest(inputData)
	} else if op%noOfTargets==1083 {
		fuzzruntimev1alpha2StartContainerResponse(inputData)
	} else if op%noOfTargets==1084 {
		fuzzruntimev1alpha2StopContainerRequest(inputData)
	} else if op%noOfTargets==1085 {
		fuzzruntimev1alpha2StopContainerResponse(inputData)
	} else if op%noOfTargets==1086 {
		fuzzruntimev1alpha2RemoveContainerRequest(inputData)
	} else if op%noOfTargets==1087 {
		fuzzruntimev1alpha2RemoveContainerResponse(inputData)
	} else if op%noOfTargets==1088 {
		fuzzruntimev1alpha2ContainerStateValue(inputData)
	} else if op%noOfTargets==1089 {
		fuzzruntimev1alpha2ContainerFilter(inputData)
	} else if op%noOfTargets==1090 {
		fuzzruntimev1alpha2ListContainersRequest(inputData)
	} else if op%noOfTargets==1091 {
		fuzzruntimev1alpha2Container(inputData)
	} else if op%noOfTargets==1092 {
		fuzzruntimev1alpha2ListContainersResponse(inputData)
	} else if op%noOfTargets==1093 {
		fuzzruntimev1alpha2ContainerStatusRequest(inputData)
	} else if op%noOfTargets==1094 {
		fuzzruntimev1alpha2ContainerStatus(inputData)
	} else if op%noOfTargets==1095 {
		fuzzruntimev1alpha2ContainerStatusResponse(inputData)
	} else if op%noOfTargets==1096 {
		fuzzruntimev1alpha2UpdateContainerResourcesRequest(inputData)
	} else if op%noOfTargets==1097 {
		fuzzruntimev1alpha2UpdateContainerResourcesResponse(inputData)
	} else if op%noOfTargets==1098 {
		fuzzruntimev1alpha2ExecSyncRequest(inputData)
	} else if op%noOfTargets==1099 {
		fuzzruntimev1alpha2ExecSyncResponse(inputData)
	} else if op%noOfTargets==1100 {
		fuzzruntimev1alpha2ExecRequest(inputData)
	} else if op%noOfTargets==1101 {
		fuzzruntimev1alpha2ExecResponse(inputData)
	} else if op%noOfTargets==1102 {
		fuzzruntimev1alpha2AttachRequest(inputData)
	} else if op%noOfTargets==1103 {
		fuzzruntimev1alpha2AttachResponse(inputData)
	} else if op%noOfTargets==1104 {
		fuzzruntimev1alpha2PortForwardRequest(inputData)
	} else if op%noOfTargets==1105 {
		fuzzruntimev1alpha2PortForwardResponse(inputData)
	} else if op%noOfTargets==1106 {
		fuzzruntimev1alpha2ImageFilter(inputData)
	} else if op%noOfTargets==1107 {
		fuzzruntimev1alpha2ListImagesRequest(inputData)
	} else if op%noOfTargets==1108 {
		fuzzruntimev1alpha2Image(inputData)
	} else if op%noOfTargets==1109 {
		fuzzruntimev1alpha2ListImagesResponse(inputData)
	} else if op%noOfTargets==1110 {
		fuzzruntimev1alpha2ImageStatusRequest(inputData)
	} else if op%noOfTargets==1111 {
		fuzzruntimev1alpha2ImageStatusResponse(inputData)
	} else if op%noOfTargets==1112 {
		fuzzruntimev1alpha2AuthConfig(inputData)
	} else if op%noOfTargets==1113 {
		fuzzruntimev1alpha2PullImageRequest(inputData)
	} else if op%noOfTargets==1114 {
		fuzzruntimev1alpha2PullImageResponse(inputData)
	} else if op%noOfTargets==1115 {
		fuzzruntimev1alpha2RemoveImageRequest(inputData)
	} else if op%noOfTargets==1116 {
		fuzzruntimev1alpha2RemoveImageResponse(inputData)
	} else if op%noOfTargets==1117 {
		fuzzruntimev1alpha2NetworkConfig(inputData)
	} else if op%noOfTargets==1118 {
		fuzzruntimev1alpha2RuntimeConfig(inputData)
	} else if op%noOfTargets==1119 {
		fuzzruntimev1alpha2UpdateRuntimeConfigRequest(inputData)
	} else if op%noOfTargets==1120 {
		fuzzruntimev1alpha2UpdateRuntimeConfigResponse(inputData)
	} else if op%noOfTargets==1121 {
		fuzzruntimev1alpha2RuntimeCondition(inputData)
	} else if op%noOfTargets==1122 {
		fuzzruntimev1alpha2RuntimeStatus(inputData)
	} else if op%noOfTargets==1123 {
		fuzzruntimev1alpha2StatusRequest(inputData)
	} else if op%noOfTargets==1124 {
		fuzzruntimev1alpha2StatusResponse(inputData)
	} else if op%noOfTargets==1125 {
		fuzzruntimev1alpha2ImageFsInfoRequest(inputData)
	} else if op%noOfTargets==1126 {
		fuzzruntimev1alpha2UInt64Value(inputData)
	} else if op%noOfTargets==1127 {
		fuzzruntimev1alpha2FilesystemIdentifier(inputData)
	} else if op%noOfTargets==1128 {
		fuzzruntimev1alpha2FilesystemUsage(inputData)
	} else if op%noOfTargets==1129 {
		fuzzruntimev1alpha2ImageFsInfoResponse(inputData)
	} else if op%noOfTargets==1130 {
		fuzzruntimev1alpha2ContainerStatsRequest(inputData)
	} else if op%noOfTargets==1131 {
		fuzzruntimev1alpha2ContainerStatsResponse(inputData)
	} else if op%noOfTargets==1132 {
		fuzzruntimev1alpha2ListContainerStatsRequest(inputData)
	} else if op%noOfTargets==1133 {
		fuzzruntimev1alpha2ContainerStatsFilter(inputData)
	} else if op%noOfTargets==1134 {
		fuzzruntimev1alpha2ListContainerStatsResponse(inputData)
	} else if op%noOfTargets==1135 {
		fuzzruntimev1alpha2ContainerAttributes(inputData)
	} else if op%noOfTargets==1136 {
		fuzzruntimev1alpha2ContainerStats(inputData)
	} else if op%noOfTargets==1137 {
		fuzzruntimev1alpha2CpuUsage(inputData)
	} else if op%noOfTargets==1138 {
		fuzzruntimev1alpha2MemoryUsage(inputData)
	} else if op%noOfTargets==1139 {
		fuzzruntimev1alpha2ReopenContainerLogRequest(inputData)
	} else if op%noOfTargets==1140 {
		fuzzruntimev1alpha2ReopenContainerLogResponse(inputData)
	} else if op%noOfTargets==1141 {
		fuzzapiregistrationv1APIService(inputData)
	} else if op%noOfTargets==1142 {
		fuzzapiregistrationv1APIServiceCondition(inputData)
	} else if op%noOfTargets==1143 {
		fuzzapiregistrationv1APIServiceList(inputData)
	} else if op%noOfTargets==1144 {
		fuzzapiregistrationv1APIServiceSpec(inputData)
	} else if op%noOfTargets==1145 {
		fuzzapiregistrationv1APIServiceStatus(inputData)
	} else if op%noOfTargets==1146 {
		fuzzapiregistrationv1ServiceReference(inputData)
	} else if op%noOfTargets==1147 {
		fuzzapiregistrationv1beta1APIService(inputData)
	} else if op%noOfTargets==1148 {
		fuzzapiregistrationv1beta1APIServiceCondition(inputData)
	} else if op%noOfTargets==1149 {
		fuzzapiregistrationv1beta1APIServiceList(inputData)
	} else if op%noOfTargets==1150 {
		fuzzapiregistrationv1beta1APIServiceSpec(inputData)
	} else if op%noOfTargets==1151 {
		fuzzapiregistrationv1beta1APIServiceStatus(inputData)
	} else if op%noOfTargets==1152 {
		fuzzapiregistrationv1beta1ServiceReference(inputData)
	} else if op%noOfTargets==1153 {
		fuzzdevicepluginv1alphaRegisterRequest(inputData)
	} else if op%noOfTargets==1154 {
		fuzzdevicepluginv1alphaEmpty(inputData)
	} else if op%noOfTargets==1155 {
		fuzzdevicepluginv1alphaListAndWatchResponse(inputData)
	} else if op%noOfTargets==1156 {
		fuzzdevicepluginv1alphaDevice(inputData)
	} else if op%noOfTargets==1157 {
		fuzzdevicepluginv1alphaAllocateRequest(inputData)
	} else if op%noOfTargets==1158 {
		fuzzdevicepluginv1alphaAllocateResponse(inputData)
	} else if op%noOfTargets==1159 {
		fuzzdevicepluginv1alphaMount(inputData)
	} else if op%noOfTargets==1160 {
		fuzzdevicepluginv1alphaDeviceSpec(inputData)
	} else if op%noOfTargets==1161 {
		fuzzdevicepluginv1beta1DevicePluginOptions(inputData)
	} else if op%noOfTargets==1162 {
		fuzzdevicepluginv1beta1RegisterRequest(inputData)
	} else if op%noOfTargets==1163 {
		fuzzdevicepluginv1beta1Empty(inputData)
	} else if op%noOfTargets==1164 {
		fuzzdevicepluginv1beta1ListAndWatchResponse(inputData)
	} else if op%noOfTargets==1165 {
		fuzzdevicepluginv1beta1TopologyInfo(inputData)
	} else if op%noOfTargets==1166 {
		fuzzdevicepluginv1beta1NUMANode(inputData)
	} else if op%noOfTargets==1167 {
		fuzzdevicepluginv1beta1Device(inputData)
	} else if op%noOfTargets==1168 {
		fuzzdevicepluginv1beta1PreStartContainerRequest(inputData)
	} else if op%noOfTargets==1169 {
		fuzzdevicepluginv1beta1PreStartContainerResponse(inputData)
	} else if op%noOfTargets==1170 {
		fuzzdevicepluginv1beta1PreferredAllocationRequest(inputData)
	} else if op%noOfTargets==1171 {
		fuzzdevicepluginv1beta1ContainerPreferredAllocationRequest(inputData)
	} else if op%noOfTargets==1172 {
		fuzzdevicepluginv1beta1PreferredAllocationResponse(inputData)
	} else if op%noOfTargets==1173 {
		fuzzdevicepluginv1beta1ContainerPreferredAllocationResponse(inputData)
	} else if op%noOfTargets==1174 {
		fuzzdevicepluginv1beta1AllocateRequest(inputData)
	} else if op%noOfTargets==1175 {
		fuzzdevicepluginv1beta1ContainerAllocateRequest(inputData)
	} else if op%noOfTargets==1176 {
		fuzzdevicepluginv1beta1AllocateResponse(inputData)
	} else if op%noOfTargets==1177 {
		fuzzdevicepluginv1beta1ContainerAllocateResponse(inputData)
	} else if op%noOfTargets==1178 {
		fuzzdevicepluginv1beta1Mount(inputData)
	} else if op%noOfTargets==1179 {
		fuzzdevicepluginv1beta1DeviceSpec(inputData)
	} else if op%noOfTargets==1180 {
		fuzzpluginregistrationv1PluginInfo(inputData)
	} else if op%noOfTargets==1181 {
		fuzzpluginregistrationv1RegistrationStatus(inputData)
	} else if op%noOfTargets==1182 {
		fuzzpluginregistrationv1RegistrationStatusResponse(inputData)
	} else if op%noOfTargets==1183 {
		fuzzpluginregistrationv1InfoRequest(inputData)
	} else if op%noOfTargets==1184 {
		fuzzpluginregistrationv1alpha1PluginInfo(inputData)
	} else if op%noOfTargets==1185 {
		fuzzpluginregistrationv1alpha1RegistrationStatus(inputData)
	} else if op%noOfTargets==1186 {
		fuzzpluginregistrationv1alpha1RegistrationStatusResponse(inputData)
	} else if op%noOfTargets==1187 {
		fuzzpluginregistrationv1alpha1InfoRequest(inputData)
	} else if op%noOfTargets==1188 {
		fuzzpluginregistrationv1beta1PluginInfo(inputData)
	} else if op%noOfTargets==1189 {
		fuzzpluginregistrationv1beta1RegistrationStatus(inputData)
	} else if op%noOfTargets==1190 {
		fuzzpluginregistrationv1beta1RegistrationStatusResponse(inputData)
	} else if op%noOfTargets==1191 {
		fuzzpluginregistrationv1beta1InfoRequest(inputData)
	} else if op%noOfTargets==1192 {
		fuzzpodresourcesv1AllocatableResourcesRequest(inputData)
	} else if op%noOfTargets==1193 {
		fuzzpodresourcesv1AllocatableResourcesResponse(inputData)
	} else if op%noOfTargets==1194 {
		fuzzpodresourcesv1ListPodResourcesRequest(inputData)
	} else if op%noOfTargets==1195 {
		fuzzpodresourcesv1ListPodResourcesResponse(inputData)
	} else if op%noOfTargets==1196 {
		fuzzpodresourcesv1PodResources(inputData)
	} else if op%noOfTargets==1197 {
		fuzzpodresourcesv1ContainerResources(inputData)
	} else if op%noOfTargets==1198 {
		fuzzpodresourcesv1ContainerMemory(inputData)
	} else if op%noOfTargets==1199 {
		fuzzpodresourcesv1ContainerDevices(inputData)
	} else if op%noOfTargets==1200 {
		fuzzpodresourcesv1TopologyInfo(inputData)
	} else if op%noOfTargets==1201 {
		fuzzpodresourcesv1NUMANode(inputData)
	} else if op%noOfTargets==1202 {
		fuzzpodresourcesv1alpha1ListPodResourcesRequest(inputData)
	} else if op%noOfTargets==1203 {
		fuzzpodresourcesv1alpha1ListPodResourcesResponse(inputData)
	} else if op%noOfTargets==1204 {
		fuzzpodresourcesv1alpha1PodResources(inputData)
	} else if op%noOfTargets==1205 {
		fuzzpodresourcesv1alpha1ContainerResources(inputData)
	} else if op%noOfTargets==1206 {
		fuzzpodresourcesv1alpha1ContainerDevices(inputData)
	} else if op%noOfTargets==1207 {
		fuzzcustom_metricsv1beta1MetricListOptions(inputData)
	} else if op%noOfTargets==1208 {
		fuzzcustom_metricsv1beta1MetricValue(inputData)
	} else if op%noOfTargets==1209 {
		fuzzcustom_metricsv1beta1MetricValueList(inputData)
	} else if op%noOfTargets==1210 {
		fuzzcustom_metricsv1beta2MetricIdentifier(inputData)
	} else if op%noOfTargets==1211 {
		fuzzcustom_metricsv1beta2MetricListOptions(inputData)
	} else if op%noOfTargets==1212 {
		fuzzcustom_metricsv1beta2MetricValue(inputData)
	} else if op%noOfTargets==1213 {
		fuzzcustom_metricsv1beta2MetricValueList(inputData)
	} else if op%noOfTargets==1214 {
		fuzzexternal_metricsv1beta1ExternalMetricValue(inputData)
	} else if op%noOfTargets==1215 {
		fuzzexternal_metricsv1beta1ExternalMetricValueList(inputData)
	} else if op%noOfTargets==1216 {
		fuzzmetricsv1alpha1ContainerMetrics(inputData)
	} else if op%noOfTargets==1217 {
		fuzzmetricsv1alpha1NodeMetrics(inputData)
	} else if op%noOfTargets==1218 {
		fuzzmetricsv1alpha1NodeMetricsList(inputData)
	} else if op%noOfTargets==1219 {
		fuzzmetricsv1alpha1PodMetrics(inputData)
	} else if op%noOfTargets==1220 {
		fuzzmetricsv1alpha1PodMetricsList(inputData)
	} else if op%noOfTargets==1221 {
		fuzzmetricsv1beta1ContainerMetrics(inputData)
	} else if op%noOfTargets==1222 {
		fuzzmetricsv1beta1NodeMetrics(inputData)
	} else if op%noOfTargets==1223 {
		fuzzmetricsv1beta1NodeMetricsList(inputData)
	} else if op%noOfTargets==1224 {
		fuzzmetricsv1beta1PodMetrics(inputData)
	} else if op%noOfTargets==1225 {
		fuzzmetricsv1beta1PodMetricsList(inputData)
	}

	return 1
}

func fuzzadmissionv1AdmissionRequest(data []byte) {
	m1 := &admissionv1.AdmissionRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionv1.AdmissionRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionv1AdmissionResponse(data []byte) {
	m1 := &admissionv1.AdmissionResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionv1.AdmissionResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionv1AdmissionReview(data []byte) {
	m1 := &admissionv1.AdmissionReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionv1.AdmissionReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionv1beta1AdmissionRequest(data []byte) {
	m1 := &admissionv1beta1.AdmissionRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionv1beta1.AdmissionRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionv1beta1AdmissionResponse(data []byte) {
	m1 := &admissionv1beta1.AdmissionResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionv1beta1.AdmissionResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionv1beta1AdmissionReview(data []byte) {
	m1 := &admissionv1beta1.AdmissionReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionv1beta1.AdmissionReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1MutatingWebhook(data []byte) {
	m1 := &admissionregistrationv1.MutatingWebhook{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1.MutatingWebhook{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1MutatingWebhookConfiguration(data []byte) {
	m1 := &admissionregistrationv1.MutatingWebhookConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1.MutatingWebhookConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1MutatingWebhookConfigurationList(data []byte) {
	m1 := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1.MutatingWebhookConfigurationList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1Rule(data []byte) {
	m1 := &admissionregistrationv1.Rule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1.Rule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1RuleWithOperations(data []byte) {
	m1 := &admissionregistrationv1.RuleWithOperations{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1.RuleWithOperations{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1ServiceReference(data []byte) {
	m1 := &admissionregistrationv1.ServiceReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1.ServiceReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1ValidatingWebhook(data []byte) {
	m1 := &admissionregistrationv1.ValidatingWebhook{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1.ValidatingWebhook{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1ValidatingWebhookConfiguration(data []byte) {
	m1 := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1.ValidatingWebhookConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1ValidatingWebhookConfigurationList(data []byte) {
	m1 := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1.ValidatingWebhookConfigurationList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1WebhookClientConfig(data []byte) {
	m1 := &admissionregistrationv1.WebhookClientConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1.WebhookClientConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1beta1MutatingWebhook(data []byte) {
	m1 := &admissionregistrationv1beta1.MutatingWebhook{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1beta1.MutatingWebhook{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1beta1MutatingWebhookConfiguration(data []byte) {
	m1 := &admissionregistrationv1beta1.MutatingWebhookConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1beta1.MutatingWebhookConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1beta1MutatingWebhookConfigurationList(data []byte) {
	m1 := &admissionregistrationv1beta1.MutatingWebhookConfigurationList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1beta1.MutatingWebhookConfigurationList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1beta1Rule(data []byte) {
	m1 := &admissionregistrationv1beta1.Rule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1beta1.Rule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1beta1RuleWithOperations(data []byte) {
	m1 := &admissionregistrationv1beta1.RuleWithOperations{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1beta1.RuleWithOperations{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1beta1ServiceReference(data []byte) {
	m1 := &admissionregistrationv1beta1.ServiceReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1beta1.ServiceReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1beta1ValidatingWebhook(data []byte) {
	m1 := &admissionregistrationv1beta1.ValidatingWebhook{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1beta1.ValidatingWebhook{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1beta1ValidatingWebhookConfiguration(data []byte) {
	m1 := &admissionregistrationv1beta1.ValidatingWebhookConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1beta1.ValidatingWebhookConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1beta1ValidatingWebhookConfigurationList(data []byte) {
	m1 := &admissionregistrationv1beta1.ValidatingWebhookConfigurationList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1beta1.ValidatingWebhookConfigurationList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzadmissionregistrationv1beta1WebhookClientConfig(data []byte) {
	m1 := &admissionregistrationv1beta1.WebhookClientConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &admissionregistrationv1beta1.WebhookClientConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiserverinternalv1alpha1ServerStorageVersion(data []byte) {
	m1 := &apiserverinternalv1alpha1.ServerStorageVersion{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiserverinternalv1alpha1.ServerStorageVersion{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiserverinternalv1alpha1StorageVersion(data []byte) {
	m1 := &apiserverinternalv1alpha1.StorageVersion{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiserverinternalv1alpha1.StorageVersion{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiserverinternalv1alpha1StorageVersionCondition(data []byte) {
	m1 := &apiserverinternalv1alpha1.StorageVersionCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiserverinternalv1alpha1.StorageVersionCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiserverinternalv1alpha1StorageVersionList(data []byte) {
	m1 := &apiserverinternalv1alpha1.StorageVersionList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiserverinternalv1alpha1.StorageVersionList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiserverinternalv1alpha1StorageVersionSpec(data []byte) {
	m1 := &apiserverinternalv1alpha1.StorageVersionSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiserverinternalv1alpha1.StorageVersionSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiserverinternalv1alpha1StorageVersionStatus(data []byte) {
	m1 := &apiserverinternalv1alpha1.StorageVersionStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiserverinternalv1alpha1.StorageVersionStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1ControllerRevision(data []byte) {
	m1 := &appsv1.ControllerRevision{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.ControllerRevision{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1ControllerRevisionList(data []byte) {
	m1 := &appsv1.ControllerRevisionList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.ControllerRevisionList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1DaemonSet(data []byte) {
	m1 := &appsv1.DaemonSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.DaemonSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1DaemonSetCondition(data []byte) {
	m1 := &appsv1.DaemonSetCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.DaemonSetCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1DaemonSetList(data []byte) {
	m1 := &appsv1.DaemonSetList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.DaemonSetList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1DaemonSetSpec(data []byte) {
	m1 := &appsv1.DaemonSetSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.DaemonSetSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1DaemonSetStatus(data []byte) {
	m1 := &appsv1.DaemonSetStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.DaemonSetStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1DaemonSetUpdateStrategy(data []byte) {
	m1 := &appsv1.DaemonSetUpdateStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.DaemonSetUpdateStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1Deployment(data []byte) {
	m1 := &appsv1.Deployment{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.Deployment{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1DeploymentCondition(data []byte) {
	m1 := &appsv1.DeploymentCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.DeploymentCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1DeploymentList(data []byte) {
	m1 := &appsv1.DeploymentList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.DeploymentList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1DeploymentSpec(data []byte) {
	m1 := &appsv1.DeploymentSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.DeploymentSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1DeploymentStatus(data []byte) {
	m1 := &appsv1.DeploymentStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.DeploymentStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1DeploymentStrategy(data []byte) {
	m1 := &appsv1.DeploymentStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.DeploymentStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1ReplicaSet(data []byte) {
	m1 := &appsv1.ReplicaSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.ReplicaSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1ReplicaSetCondition(data []byte) {
	m1 := &appsv1.ReplicaSetCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.ReplicaSetCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1ReplicaSetList(data []byte) {
	m1 := &appsv1.ReplicaSetList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.ReplicaSetList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1ReplicaSetSpec(data []byte) {
	m1 := &appsv1.ReplicaSetSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.ReplicaSetSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1ReplicaSetStatus(data []byte) {
	m1 := &appsv1.ReplicaSetStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.ReplicaSetStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1RollingUpdateDaemonSet(data []byte) {
	m1 := &appsv1.RollingUpdateDaemonSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.RollingUpdateDaemonSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1RollingUpdateDeployment(data []byte) {
	m1 := &appsv1.RollingUpdateDeployment{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.RollingUpdateDeployment{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1RollingUpdateStatefulSetStrategy(data []byte) {
	m1 := &appsv1.RollingUpdateStatefulSetStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.RollingUpdateStatefulSetStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1StatefulSet(data []byte) {
	m1 := &appsv1.StatefulSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.StatefulSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1StatefulSetCondition(data []byte) {
	m1 := &appsv1.StatefulSetCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.StatefulSetCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1StatefulSetList(data []byte) {
	m1 := &appsv1.StatefulSetList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.StatefulSetList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1StatefulSetPersistentVolumeClaimRetentionPolicy(data []byte) {
	m1 := &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.StatefulSetPersistentVolumeClaimRetentionPolicy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1StatefulSetSpec(data []byte) {
	m1 := &appsv1.StatefulSetSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.StatefulSetSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1StatefulSetStatus(data []byte) {
	m1 := &appsv1.StatefulSetStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.StatefulSetStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1StatefulSetUpdateStrategy(data []byte) {
	m1 := &appsv1.StatefulSetUpdateStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1.StatefulSetUpdateStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1ControllerRevision(data []byte) {
	m1 := &appsv1beta1.ControllerRevision{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.ControllerRevision{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1ControllerRevisionList(data []byte) {
	m1 := &appsv1beta1.ControllerRevisionList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.ControllerRevisionList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1Deployment(data []byte) {
	m1 := &appsv1beta1.Deployment{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.Deployment{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1DeploymentCondition(data []byte) {
	m1 := &appsv1beta1.DeploymentCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.DeploymentCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1DeploymentList(data []byte) {
	m1 := &appsv1beta1.DeploymentList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.DeploymentList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1DeploymentRollback(data []byte) {
	m1 := &appsv1beta1.DeploymentRollback{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.DeploymentRollback{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1DeploymentSpec(data []byte) {
	m1 := &appsv1beta1.DeploymentSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.DeploymentSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1DeploymentStatus(data []byte) {
	m1 := &appsv1beta1.DeploymentStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.DeploymentStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1DeploymentStrategy(data []byte) {
	m1 := &appsv1beta1.DeploymentStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.DeploymentStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1RollbackConfig(data []byte) {
	m1 := &appsv1beta1.RollbackConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.RollbackConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1RollingUpdateDeployment(data []byte) {
	m1 := &appsv1beta1.RollingUpdateDeployment{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.RollingUpdateDeployment{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1RollingUpdateStatefulSetStrategy(data []byte) {
	m1 := &appsv1beta1.RollingUpdateStatefulSetStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.RollingUpdateStatefulSetStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1Scale(data []byte) {
	m1 := &appsv1beta1.Scale{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.Scale{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1ScaleSpec(data []byte) {
	m1 := &appsv1beta1.ScaleSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.ScaleSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1ScaleStatus(data []byte) {
	m1 := &appsv1beta1.ScaleStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.ScaleStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1StatefulSet(data []byte) {
	m1 := &appsv1beta1.StatefulSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.StatefulSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1StatefulSetCondition(data []byte) {
	m1 := &appsv1beta1.StatefulSetCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.StatefulSetCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1StatefulSetList(data []byte) {
	m1 := &appsv1beta1.StatefulSetList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.StatefulSetList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1StatefulSetPersistentVolumeClaimRetentionPolicy(data []byte) {
	m1 := &appsv1beta1.StatefulSetPersistentVolumeClaimRetentionPolicy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.StatefulSetPersistentVolumeClaimRetentionPolicy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1StatefulSetSpec(data []byte) {
	m1 := &appsv1beta1.StatefulSetSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.StatefulSetSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1StatefulSetStatus(data []byte) {
	m1 := &appsv1beta1.StatefulSetStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.StatefulSetStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta1StatefulSetUpdateStrategy(data []byte) {
	m1 := &appsv1beta1.StatefulSetUpdateStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta1.StatefulSetUpdateStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2ControllerRevision(data []byte) {
	m1 := &appsv1beta2.ControllerRevision{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.ControllerRevision{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2ControllerRevisionList(data []byte) {
	m1 := &appsv1beta2.ControllerRevisionList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.ControllerRevisionList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2DaemonSet(data []byte) {
	m1 := &appsv1beta2.DaemonSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.DaemonSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2DaemonSetCondition(data []byte) {
	m1 := &appsv1beta2.DaemonSetCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.DaemonSetCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2DaemonSetList(data []byte) {
	m1 := &appsv1beta2.DaemonSetList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.DaemonSetList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2DaemonSetSpec(data []byte) {
	m1 := &appsv1beta2.DaemonSetSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.DaemonSetSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2DaemonSetStatus(data []byte) {
	m1 := &appsv1beta2.DaemonSetStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.DaemonSetStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2DaemonSetUpdateStrategy(data []byte) {
	m1 := &appsv1beta2.DaemonSetUpdateStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.DaemonSetUpdateStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2Deployment(data []byte) {
	m1 := &appsv1beta2.Deployment{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.Deployment{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2DeploymentCondition(data []byte) {
	m1 := &appsv1beta2.DeploymentCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.DeploymentCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2DeploymentList(data []byte) {
	m1 := &appsv1beta2.DeploymentList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.DeploymentList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2DeploymentSpec(data []byte) {
	m1 := &appsv1beta2.DeploymentSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.DeploymentSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2DeploymentStatus(data []byte) {
	m1 := &appsv1beta2.DeploymentStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.DeploymentStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2DeploymentStrategy(data []byte) {
	m1 := &appsv1beta2.DeploymentStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.DeploymentStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2ReplicaSet(data []byte) {
	m1 := &appsv1beta2.ReplicaSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.ReplicaSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2ReplicaSetCondition(data []byte) {
	m1 := &appsv1beta2.ReplicaSetCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.ReplicaSetCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2ReplicaSetList(data []byte) {
	m1 := &appsv1beta2.ReplicaSetList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.ReplicaSetList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2ReplicaSetSpec(data []byte) {
	m1 := &appsv1beta2.ReplicaSetSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.ReplicaSetSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2ReplicaSetStatus(data []byte) {
	m1 := &appsv1beta2.ReplicaSetStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.ReplicaSetStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2RollingUpdateDaemonSet(data []byte) {
	m1 := &appsv1beta2.RollingUpdateDaemonSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.RollingUpdateDaemonSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2RollingUpdateDeployment(data []byte) {
	m1 := &appsv1beta2.RollingUpdateDeployment{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.RollingUpdateDeployment{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2RollingUpdateStatefulSetStrategy(data []byte) {
	m1 := &appsv1beta2.RollingUpdateStatefulSetStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.RollingUpdateStatefulSetStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2Scale(data []byte) {
	m1 := &appsv1beta2.Scale{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.Scale{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2ScaleSpec(data []byte) {
	m1 := &appsv1beta2.ScaleSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.ScaleSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2ScaleStatus(data []byte) {
	m1 := &appsv1beta2.ScaleStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.ScaleStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2StatefulSet(data []byte) {
	m1 := &appsv1beta2.StatefulSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.StatefulSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2StatefulSetCondition(data []byte) {
	m1 := &appsv1beta2.StatefulSetCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.StatefulSetCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2StatefulSetList(data []byte) {
	m1 := &appsv1beta2.StatefulSetList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.StatefulSetList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2StatefulSetPersistentVolumeClaimRetentionPolicy(data []byte) {
	m1 := &appsv1beta2.StatefulSetPersistentVolumeClaimRetentionPolicy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.StatefulSetPersistentVolumeClaimRetentionPolicy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2StatefulSetSpec(data []byte) {
	m1 := &appsv1beta2.StatefulSetSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.StatefulSetSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2StatefulSetStatus(data []byte) {
	m1 := &appsv1beta2.StatefulSetStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.StatefulSetStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzappsv1beta2StatefulSetUpdateStrategy(data []byte) {
	m1 := &appsv1beta2.StatefulSetUpdateStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &appsv1beta2.StatefulSetUpdateStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1BoundObjectReference(data []byte) {
	m1 := &authenticationv1.BoundObjectReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1.BoundObjectReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1TokenRequest(data []byte) {
	m1 := &authenticationv1.TokenRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1.TokenRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1TokenRequestSpec(data []byte) {
	m1 := &authenticationv1.TokenRequestSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1.TokenRequestSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1TokenRequestStatus(data []byte) {
	m1 := &authenticationv1.TokenRequestStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1.TokenRequestStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1TokenReview(data []byte) {
	m1 := &authenticationv1.TokenReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1.TokenReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1TokenReviewSpec(data []byte) {
	m1 := &authenticationv1.TokenReviewSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1.TokenReviewSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1TokenReviewStatus(data []byte) {
	m1 := &authenticationv1.TokenReviewStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1.TokenReviewStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1UserInfo(data []byte) {
	m1 := &authenticationv1.UserInfo{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1.UserInfo{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1beta1TokenReview(data []byte) {
	m1 := &authenticationv1beta1.TokenReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1beta1.TokenReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1beta1TokenReviewSpec(data []byte) {
	m1 := &authenticationv1beta1.TokenReviewSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1beta1.TokenReviewSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1beta1TokenReviewStatus(data []byte) {
	m1 := &authenticationv1beta1.TokenReviewStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1beta1.TokenReviewStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthenticationv1beta1UserInfo(data []byte) {
	m1 := &authenticationv1beta1.UserInfo{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authenticationv1beta1.UserInfo{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1LocalSubjectAccessReview(data []byte) {
	m1 := &authorizationv1.LocalSubjectAccessReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.LocalSubjectAccessReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1NonResourceAttributes(data []byte) {
	m1 := &authorizationv1.NonResourceAttributes{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.NonResourceAttributes{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1NonResourceRule(data []byte) {
	m1 := &authorizationv1.NonResourceRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.NonResourceRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1ResourceAttributes(data []byte) {
	m1 := &authorizationv1.ResourceAttributes{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.ResourceAttributes{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1ResourceRule(data []byte) {
	m1 := &authorizationv1.ResourceRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.ResourceRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1SelfSubjectAccessReview(data []byte) {
	m1 := &authorizationv1.SelfSubjectAccessReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.SelfSubjectAccessReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1SelfSubjectAccessReviewSpec(data []byte) {
	m1 := &authorizationv1.SelfSubjectAccessReviewSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.SelfSubjectAccessReviewSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1SelfSubjectRulesReview(data []byte) {
	m1 := &authorizationv1.SelfSubjectRulesReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.SelfSubjectRulesReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1SelfSubjectRulesReviewSpec(data []byte) {
	m1 := &authorizationv1.SelfSubjectRulesReviewSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.SelfSubjectRulesReviewSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1SubjectAccessReview(data []byte) {
	m1 := &authorizationv1.SubjectAccessReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.SubjectAccessReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1SubjectAccessReviewSpec(data []byte) {
	m1 := &authorizationv1.SubjectAccessReviewSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.SubjectAccessReviewSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1SubjectAccessReviewStatus(data []byte) {
	m1 := &authorizationv1.SubjectAccessReviewStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.SubjectAccessReviewStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1SubjectRulesReviewStatus(data []byte) {
	m1 := &authorizationv1.SubjectRulesReviewStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1.SubjectRulesReviewStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1LocalSubjectAccessReview(data []byte) {
	m1 := &authorizationv1beta1.LocalSubjectAccessReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.LocalSubjectAccessReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1NonResourceAttributes(data []byte) {
	m1 := &authorizationv1beta1.NonResourceAttributes{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.NonResourceAttributes{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1NonResourceRule(data []byte) {
	m1 := &authorizationv1beta1.NonResourceRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.NonResourceRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1ResourceAttributes(data []byte) {
	m1 := &authorizationv1beta1.ResourceAttributes{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.ResourceAttributes{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1ResourceRule(data []byte) {
	m1 := &authorizationv1beta1.ResourceRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.ResourceRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1SelfSubjectAccessReview(data []byte) {
	m1 := &authorizationv1beta1.SelfSubjectAccessReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.SelfSubjectAccessReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1SelfSubjectAccessReviewSpec(data []byte) {
	m1 := &authorizationv1beta1.SelfSubjectAccessReviewSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.SelfSubjectAccessReviewSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1SelfSubjectRulesReview(data []byte) {
	m1 := &authorizationv1beta1.SelfSubjectRulesReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.SelfSubjectRulesReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1SelfSubjectRulesReviewSpec(data []byte) {
	m1 := &authorizationv1beta1.SelfSubjectRulesReviewSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.SelfSubjectRulesReviewSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1SubjectAccessReview(data []byte) {
	m1 := &authorizationv1beta1.SubjectAccessReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.SubjectAccessReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1SubjectAccessReviewSpec(data []byte) {
	m1 := &authorizationv1beta1.SubjectAccessReviewSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.SubjectAccessReviewSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1SubjectAccessReviewStatus(data []byte) {
	m1 := &authorizationv1beta1.SubjectAccessReviewStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.SubjectAccessReviewStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauthorizationv1beta1SubjectRulesReviewStatus(data []byte) {
	m1 := &authorizationv1beta1.SubjectRulesReviewStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &authorizationv1beta1.SubjectRulesReviewStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1ContainerResourceMetricSource(data []byte) {
	m1 := &autoscalingv1.ContainerResourceMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.ContainerResourceMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1ContainerResourceMetricStatus(data []byte) {
	m1 := &autoscalingv1.ContainerResourceMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.ContainerResourceMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1CrossVersionObjectReference(data []byte) {
	m1 := &autoscalingv1.CrossVersionObjectReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.CrossVersionObjectReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1ExternalMetricSource(data []byte) {
	m1 := &autoscalingv1.ExternalMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.ExternalMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1ExternalMetricStatus(data []byte) {
	m1 := &autoscalingv1.ExternalMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.ExternalMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1HorizontalPodAutoscaler(data []byte) {
	m1 := &autoscalingv1.HorizontalPodAutoscaler{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.HorizontalPodAutoscaler{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1HorizontalPodAutoscalerCondition(data []byte) {
	m1 := &autoscalingv1.HorizontalPodAutoscalerCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.HorizontalPodAutoscalerCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1HorizontalPodAutoscalerList(data []byte) {
	m1 := &autoscalingv1.HorizontalPodAutoscalerList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.HorizontalPodAutoscalerList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1HorizontalPodAutoscalerSpec(data []byte) {
	m1 := &autoscalingv1.HorizontalPodAutoscalerSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.HorizontalPodAutoscalerSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1HorizontalPodAutoscalerStatus(data []byte) {
	m1 := &autoscalingv1.HorizontalPodAutoscalerStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.HorizontalPodAutoscalerStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1MetricSpec(data []byte) {
	m1 := &autoscalingv1.MetricSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.MetricSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1MetricStatus(data []byte) {
	m1 := &autoscalingv1.MetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.MetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1ObjectMetricSource(data []byte) {
	m1 := &autoscalingv1.ObjectMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.ObjectMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1ObjectMetricStatus(data []byte) {
	m1 := &autoscalingv1.ObjectMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.ObjectMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1PodsMetricSource(data []byte) {
	m1 := &autoscalingv1.PodsMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.PodsMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1PodsMetricStatus(data []byte) {
	m1 := &autoscalingv1.PodsMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.PodsMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1ResourceMetricSource(data []byte) {
	m1 := &autoscalingv1.ResourceMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.ResourceMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1ResourceMetricStatus(data []byte) {
	m1 := &autoscalingv1.ResourceMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.ResourceMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1Scale(data []byte) {
	m1 := &autoscalingv1.Scale{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.Scale{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1ScaleSpec(data []byte) {
	m1 := &autoscalingv1.ScaleSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.ScaleSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv1ScaleStatus(data []byte) {
	m1 := &autoscalingv1.ScaleStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv1.ScaleStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2ContainerResourceMetricSource(data []byte) {
	m1 := &autoscalingv2.ContainerResourceMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.ContainerResourceMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2ContainerResourceMetricStatus(data []byte) {
	m1 := &autoscalingv2.ContainerResourceMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.ContainerResourceMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2CrossVersionObjectReference(data []byte) {
	m1 := &autoscalingv2.CrossVersionObjectReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.CrossVersionObjectReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2ExternalMetricSource(data []byte) {
	m1 := &autoscalingv2.ExternalMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.ExternalMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2ExternalMetricStatus(data []byte) {
	m1 := &autoscalingv2.ExternalMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.ExternalMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2HPAScalingPolicy(data []byte) {
	m1 := &autoscalingv2.HPAScalingPolicy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.HPAScalingPolicy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2HPAScalingRules(data []byte) {
	m1 := &autoscalingv2.HPAScalingRules{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.HPAScalingRules{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2HorizontalPodAutoscaler(data []byte) {
	m1 := &autoscalingv2.HorizontalPodAutoscaler{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.HorizontalPodAutoscaler{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2HorizontalPodAutoscalerBehavior(data []byte) {
	m1 := &autoscalingv2.HorizontalPodAutoscalerBehavior{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.HorizontalPodAutoscalerBehavior{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2HorizontalPodAutoscalerCondition(data []byte) {
	m1 := &autoscalingv2.HorizontalPodAutoscalerCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.HorizontalPodAutoscalerCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2HorizontalPodAutoscalerList(data []byte) {
	m1 := &autoscalingv2.HorizontalPodAutoscalerList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.HorizontalPodAutoscalerList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2HorizontalPodAutoscalerSpec(data []byte) {
	m1 := &autoscalingv2.HorizontalPodAutoscalerSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.HorizontalPodAutoscalerSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2HorizontalPodAutoscalerStatus(data []byte) {
	m1 := &autoscalingv2.HorizontalPodAutoscalerStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.HorizontalPodAutoscalerStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2MetricIdentifier(data []byte) {
	m1 := &autoscalingv2.MetricIdentifier{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.MetricIdentifier{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2MetricSpec(data []byte) {
	m1 := &autoscalingv2.MetricSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.MetricSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2MetricStatus(data []byte) {
	m1 := &autoscalingv2.MetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.MetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2MetricTarget(data []byte) {
	m1 := &autoscalingv2.MetricTarget{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.MetricTarget{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2MetricValueStatus(data []byte) {
	m1 := &autoscalingv2.MetricValueStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.MetricValueStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2ObjectMetricSource(data []byte) {
	m1 := &autoscalingv2.ObjectMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.ObjectMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2ObjectMetricStatus(data []byte) {
	m1 := &autoscalingv2.ObjectMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.ObjectMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2PodsMetricSource(data []byte) {
	m1 := &autoscalingv2.PodsMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.PodsMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2PodsMetricStatus(data []byte) {
	m1 := &autoscalingv2.PodsMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.PodsMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2ResourceMetricSource(data []byte) {
	m1 := &autoscalingv2.ResourceMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.ResourceMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2ResourceMetricStatus(data []byte) {
	m1 := &autoscalingv2.ResourceMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2.ResourceMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1ContainerResourceMetricSource(data []byte) {
	m1 := &autoscalingv2beta1.ContainerResourceMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.ContainerResourceMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1ContainerResourceMetricStatus(data []byte) {
	m1 := &autoscalingv2beta1.ContainerResourceMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.ContainerResourceMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1CrossVersionObjectReference(data []byte) {
	m1 := &autoscalingv2beta1.CrossVersionObjectReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.CrossVersionObjectReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1ExternalMetricSource(data []byte) {
	m1 := &autoscalingv2beta1.ExternalMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.ExternalMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1ExternalMetricStatus(data []byte) {
	m1 := &autoscalingv2beta1.ExternalMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.ExternalMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1HorizontalPodAutoscaler(data []byte) {
	m1 := &autoscalingv2beta1.HorizontalPodAutoscaler{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.HorizontalPodAutoscaler{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1HorizontalPodAutoscalerCondition(data []byte) {
	m1 := &autoscalingv2beta1.HorizontalPodAutoscalerCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.HorizontalPodAutoscalerCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1HorizontalPodAutoscalerList(data []byte) {
	m1 := &autoscalingv2beta1.HorizontalPodAutoscalerList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.HorizontalPodAutoscalerList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1HorizontalPodAutoscalerSpec(data []byte) {
	m1 := &autoscalingv2beta1.HorizontalPodAutoscalerSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.HorizontalPodAutoscalerSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1HorizontalPodAutoscalerStatus(data []byte) {
	m1 := &autoscalingv2beta1.HorizontalPodAutoscalerStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.HorizontalPodAutoscalerStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1MetricSpec(data []byte) {
	m1 := &autoscalingv2beta1.MetricSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.MetricSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1MetricStatus(data []byte) {
	m1 := &autoscalingv2beta1.MetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.MetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1ObjectMetricSource(data []byte) {
	m1 := &autoscalingv2beta1.ObjectMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.ObjectMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1ObjectMetricStatus(data []byte) {
	m1 := &autoscalingv2beta1.ObjectMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.ObjectMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1PodsMetricSource(data []byte) {
	m1 := &autoscalingv2beta1.PodsMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.PodsMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1PodsMetricStatus(data []byte) {
	m1 := &autoscalingv2beta1.PodsMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.PodsMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1ResourceMetricSource(data []byte) {
	m1 := &autoscalingv2beta1.ResourceMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.ResourceMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta1ResourceMetricStatus(data []byte) {
	m1 := &autoscalingv2beta1.ResourceMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta1.ResourceMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2ContainerResourceMetricSource(data []byte) {
	m1 := &autoscalingv2beta2.ContainerResourceMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.ContainerResourceMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2ContainerResourceMetricStatus(data []byte) {
	m1 := &autoscalingv2beta2.ContainerResourceMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.ContainerResourceMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2CrossVersionObjectReference(data []byte) {
	m1 := &autoscalingv2beta2.CrossVersionObjectReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.CrossVersionObjectReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2ExternalMetricSource(data []byte) {
	m1 := &autoscalingv2beta2.ExternalMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.ExternalMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2ExternalMetricStatus(data []byte) {
	m1 := &autoscalingv2beta2.ExternalMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.ExternalMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2HPAScalingPolicy(data []byte) {
	m1 := &autoscalingv2beta2.HPAScalingPolicy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.HPAScalingPolicy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2HPAScalingRules(data []byte) {
	m1 := &autoscalingv2beta2.HPAScalingRules{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.HPAScalingRules{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2HorizontalPodAutoscaler(data []byte) {
	m1 := &autoscalingv2beta2.HorizontalPodAutoscaler{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.HorizontalPodAutoscaler{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2HorizontalPodAutoscalerBehavior(data []byte) {
	m1 := &autoscalingv2beta2.HorizontalPodAutoscalerBehavior{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.HorizontalPodAutoscalerBehavior{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2HorizontalPodAutoscalerCondition(data []byte) {
	m1 := &autoscalingv2beta2.HorizontalPodAutoscalerCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.HorizontalPodAutoscalerCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2HorizontalPodAutoscalerList(data []byte) {
	m1 := &autoscalingv2beta2.HorizontalPodAutoscalerList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.HorizontalPodAutoscalerList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2HorizontalPodAutoscalerSpec(data []byte) {
	m1 := &autoscalingv2beta2.HorizontalPodAutoscalerSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.HorizontalPodAutoscalerSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2HorizontalPodAutoscalerStatus(data []byte) {
	m1 := &autoscalingv2beta2.HorizontalPodAutoscalerStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.HorizontalPodAutoscalerStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2MetricIdentifier(data []byte) {
	m1 := &autoscalingv2beta2.MetricIdentifier{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.MetricIdentifier{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2MetricSpec(data []byte) {
	m1 := &autoscalingv2beta2.MetricSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.MetricSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2MetricStatus(data []byte) {
	m1 := &autoscalingv2beta2.MetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.MetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2MetricTarget(data []byte) {
	m1 := &autoscalingv2beta2.MetricTarget{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.MetricTarget{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2MetricValueStatus(data []byte) {
	m1 := &autoscalingv2beta2.MetricValueStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.MetricValueStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2ObjectMetricSource(data []byte) {
	m1 := &autoscalingv2beta2.ObjectMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.ObjectMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2ObjectMetricStatus(data []byte) {
	m1 := &autoscalingv2beta2.ObjectMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.ObjectMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2PodsMetricSource(data []byte) {
	m1 := &autoscalingv2beta2.PodsMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.PodsMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2PodsMetricStatus(data []byte) {
	m1 := &autoscalingv2beta2.PodsMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.PodsMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2ResourceMetricSource(data []byte) {
	m1 := &autoscalingv2beta2.ResourceMetricSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.ResourceMetricSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzautoscalingv2beta2ResourceMetricStatus(data []byte) {
	m1 := &autoscalingv2beta2.ResourceMetricStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &autoscalingv2beta2.ResourceMetricStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1CronJob(data []byte) {
	m1 := &batchv1.CronJob{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1.CronJob{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1CronJobList(data []byte) {
	m1 := &batchv1.CronJobList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1.CronJobList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1CronJobSpec(data []byte) {
	m1 := &batchv1.CronJobSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1.CronJobSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1CronJobStatus(data []byte) {
	m1 := &batchv1.CronJobStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1.CronJobStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1Job(data []byte) {
	m1 := &batchv1.Job{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1.Job{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1JobCondition(data []byte) {
	m1 := &batchv1.JobCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1.JobCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1JobList(data []byte) {
	m1 := &batchv1.JobList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1.JobList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1JobSpec(data []byte) {
	m1 := &batchv1.JobSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1.JobSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1JobStatus(data []byte) {
	m1 := &batchv1.JobStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1.JobStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1JobTemplateSpec(data []byte) {
	m1 := &batchv1.JobTemplateSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1.JobTemplateSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1UncountedTerminatedPods(data []byte) {
	m1 := &batchv1.UncountedTerminatedPods{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1.UncountedTerminatedPods{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1beta1CronJob(data []byte) {
	m1 := &batchv1beta1.CronJob{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1beta1.CronJob{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1beta1CronJobList(data []byte) {
	m1 := &batchv1beta1.CronJobList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1beta1.CronJobList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1beta1CronJobSpec(data []byte) {
	m1 := &batchv1beta1.CronJobSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1beta1.CronJobSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1beta1CronJobStatus(data []byte) {
	m1 := &batchv1beta1.CronJobStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1beta1.CronJobStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1beta1JobTemplate(data []byte) {
	m1 := &batchv1beta1.JobTemplate{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1beta1.JobTemplate{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzbatchv1beta1JobTemplateSpec(data []byte) {
	m1 := &batchv1beta1.JobTemplateSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &batchv1beta1.JobTemplateSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcertificatesv1CertificateSigningRequest(data []byte) {
	m1 := &certificatesv1.CertificateSigningRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &certificatesv1.CertificateSigningRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcertificatesv1CertificateSigningRequestCondition(data []byte) {
	m1 := &certificatesv1.CertificateSigningRequestCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &certificatesv1.CertificateSigningRequestCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcertificatesv1CertificateSigningRequestList(data []byte) {
	m1 := &certificatesv1.CertificateSigningRequestList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &certificatesv1.CertificateSigningRequestList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcertificatesv1CertificateSigningRequestSpec(data []byte) {
	m1 := &certificatesv1.CertificateSigningRequestSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &certificatesv1.CertificateSigningRequestSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcertificatesv1CertificateSigningRequestStatus(data []byte) {
	m1 := &certificatesv1.CertificateSigningRequestStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &certificatesv1.CertificateSigningRequestStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcertificatesv1beta1CertificateSigningRequest(data []byte) {
	m1 := &certificatesv1beta1.CertificateSigningRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &certificatesv1beta1.CertificateSigningRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcertificatesv1beta1CertificateSigningRequestCondition(data []byte) {
	m1 := &certificatesv1beta1.CertificateSigningRequestCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &certificatesv1beta1.CertificateSigningRequestCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcertificatesv1beta1CertificateSigningRequestList(data []byte) {
	m1 := &certificatesv1beta1.CertificateSigningRequestList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &certificatesv1beta1.CertificateSigningRequestList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcertificatesv1beta1CertificateSigningRequestSpec(data []byte) {
	m1 := &certificatesv1beta1.CertificateSigningRequestSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &certificatesv1beta1.CertificateSigningRequestSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcertificatesv1beta1CertificateSigningRequestStatus(data []byte) {
	m1 := &certificatesv1beta1.CertificateSigningRequestStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &certificatesv1beta1.CertificateSigningRequestStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcoordinationv1Lease(data []byte) {
	m1 := &coordinationv1.Lease{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &coordinationv1.Lease{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcoordinationv1LeaseList(data []byte) {
	m1 := &coordinationv1.LeaseList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &coordinationv1.LeaseList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcoordinationv1LeaseSpec(data []byte) {
	m1 := &coordinationv1.LeaseSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &coordinationv1.LeaseSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcoordinationv1beta1Lease(data []byte) {
	m1 := &coordinationv1beta1.Lease{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &coordinationv1beta1.Lease{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcoordinationv1beta1LeaseList(data []byte) {
	m1 := &coordinationv1beta1.LeaseList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &coordinationv1beta1.LeaseList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcoordinationv1beta1LeaseSpec(data []byte) {
	m1 := &coordinationv1beta1.LeaseSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &coordinationv1beta1.LeaseSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1AWSElasticBlockStoreVolumeSource(data []byte) {
	m1 := &corev1.AWSElasticBlockStoreVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.AWSElasticBlockStoreVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Affinity(data []byte) {
	m1 := &corev1.Affinity{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Affinity{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1AttachedVolume(data []byte) {
	m1 := &corev1.AttachedVolume{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.AttachedVolume{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1AvoidPods(data []byte) {
	m1 := &corev1.AvoidPods{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.AvoidPods{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1AzureDiskVolumeSource(data []byte) {
	m1 := &corev1.AzureDiskVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.AzureDiskVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1AzureFilePersistentVolumeSource(data []byte) {
	m1 := &corev1.AzureFilePersistentVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.AzureFilePersistentVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1AzureFileVolumeSource(data []byte) {
	m1 := &corev1.AzureFileVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.AzureFileVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Binding(data []byte) {
	m1 := &corev1.Binding{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Binding{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1CSIPersistentVolumeSource(data []byte) {
	m1 := &corev1.CSIPersistentVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.CSIPersistentVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1CSIVolumeSource(data []byte) {
	m1 := &corev1.CSIVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.CSIVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Capabilities(data []byte) {
	m1 := &corev1.Capabilities{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Capabilities{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1CephFSPersistentVolumeSource(data []byte) {
	m1 := &corev1.CephFSPersistentVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.CephFSPersistentVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1CephFSVolumeSource(data []byte) {
	m1 := &corev1.CephFSVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.CephFSVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1CinderPersistentVolumeSource(data []byte) {
	m1 := &corev1.CinderPersistentVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.CinderPersistentVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1CinderVolumeSource(data []byte) {
	m1 := &corev1.CinderVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.CinderVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ClientIPConfig(data []byte) {
	m1 := &corev1.ClientIPConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ClientIPConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ComponentCondition(data []byte) {
	m1 := &corev1.ComponentCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ComponentCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ComponentStatus(data []byte) {
	m1 := &corev1.ComponentStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ComponentStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ComponentStatusList(data []byte) {
	m1 := &corev1.ComponentStatusList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ComponentStatusList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ConfigMap(data []byte) {
	m1 := &corev1.ConfigMap{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ConfigMap{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ConfigMapEnvSource(data []byte) {
	m1 := &corev1.ConfigMapEnvSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ConfigMapEnvSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ConfigMapKeySelector(data []byte) {
	m1 := &corev1.ConfigMapKeySelector{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ConfigMapKeySelector{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ConfigMapList(data []byte) {
	m1 := &corev1.ConfigMapList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ConfigMapList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ConfigMapNodeConfigSource(data []byte) {
	m1 := &corev1.ConfigMapNodeConfigSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ConfigMapNodeConfigSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ConfigMapProjection(data []byte) {
	m1 := &corev1.ConfigMapProjection{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ConfigMapProjection{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ConfigMapVolumeSource(data []byte) {
	m1 := &corev1.ConfigMapVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ConfigMapVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Container(data []byte) {
	m1 := &corev1.Container{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Container{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ContainerImage(data []byte) {
	m1 := &corev1.ContainerImage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ContainerImage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ContainerPort(data []byte) {
	m1 := &corev1.ContainerPort{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ContainerPort{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ContainerState(data []byte) {
	m1 := &corev1.ContainerState{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ContainerState{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ContainerStateRunning(data []byte) {
	m1 := &corev1.ContainerStateRunning{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ContainerStateRunning{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ContainerStateTerminated(data []byte) {
	m1 := &corev1.ContainerStateTerminated{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ContainerStateTerminated{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ContainerStateWaiting(data []byte) {
	m1 := &corev1.ContainerStateWaiting{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ContainerStateWaiting{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ContainerStatus(data []byte) {
	m1 := &corev1.ContainerStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ContainerStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1DaemonEndpoint(data []byte) {
	m1 := &corev1.DaemonEndpoint{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.DaemonEndpoint{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1DownwardAPIProjection(data []byte) {
	m1 := &corev1.DownwardAPIProjection{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.DownwardAPIProjection{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1DownwardAPIVolumeFile(data []byte) {
	m1 := &corev1.DownwardAPIVolumeFile{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.DownwardAPIVolumeFile{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1DownwardAPIVolumeSource(data []byte) {
	m1 := &corev1.DownwardAPIVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.DownwardAPIVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EmptyDirVolumeSource(data []byte) {
	m1 := &corev1.EmptyDirVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EmptyDirVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EndpointAddress(data []byte) {
	m1 := &corev1.EndpointAddress{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EndpointAddress{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EndpointPort(data []byte) {
	m1 := &corev1.EndpointPort{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EndpointPort{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EndpointSubset(data []byte) {
	m1 := &corev1.EndpointSubset{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EndpointSubset{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Endpoints(data []byte) {
	m1 := &corev1.Endpoints{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Endpoints{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EndpointsList(data []byte) {
	m1 := &corev1.EndpointsList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EndpointsList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EnvFromSource(data []byte) {
	m1 := &corev1.EnvFromSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EnvFromSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EnvVar(data []byte) {
	m1 := &corev1.EnvVar{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EnvVar{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EnvVarSource(data []byte) {
	m1 := &corev1.EnvVarSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EnvVarSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EphemeralContainer(data []byte) {
	m1 := &corev1.EphemeralContainer{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EphemeralContainer{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EphemeralContainerCommon(data []byte) {
	m1 := &corev1.EphemeralContainerCommon{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EphemeralContainerCommon{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EphemeralVolumeSource(data []byte) {
	m1 := &corev1.EphemeralVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EphemeralVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Event(data []byte) {
	m1 := &corev1.Event{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Event{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EventList(data []byte) {
	m1 := &corev1.EventList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EventList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EventSeries(data []byte) {
	m1 := &corev1.EventSeries{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EventSeries{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1EventSource(data []byte) {
	m1 := &corev1.EventSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.EventSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ExecAction(data []byte) {
	m1 := &corev1.ExecAction{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ExecAction{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1FCVolumeSource(data []byte) {
	m1 := &corev1.FCVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.FCVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1FlexPersistentVolumeSource(data []byte) {
	m1 := &corev1.FlexPersistentVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.FlexPersistentVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1FlexVolumeSource(data []byte) {
	m1 := &corev1.FlexVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.FlexVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1FlockerVolumeSource(data []byte) {
	m1 := &corev1.FlockerVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.FlockerVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1GCEPersistentDiskVolumeSource(data []byte) {
	m1 := &corev1.GCEPersistentDiskVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.GCEPersistentDiskVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1GRPCAction(data []byte) {
	m1 := &corev1.GRPCAction{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.GRPCAction{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1GitRepoVolumeSource(data []byte) {
	m1 := &corev1.GitRepoVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.GitRepoVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1GlusterfsPersistentVolumeSource(data []byte) {
	m1 := &corev1.GlusterfsPersistentVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.GlusterfsPersistentVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1GlusterfsVolumeSource(data []byte) {
	m1 := &corev1.GlusterfsVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.GlusterfsVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1HTTPGetAction(data []byte) {
	m1 := &corev1.HTTPGetAction{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.HTTPGetAction{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1HTTPHeader(data []byte) {
	m1 := &corev1.HTTPHeader{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.HTTPHeader{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1HostAlias(data []byte) {
	m1 := &corev1.HostAlias{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.HostAlias{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1HostPathVolumeSource(data []byte) {
	m1 := &corev1.HostPathVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.HostPathVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ISCSIPersistentVolumeSource(data []byte) {
	m1 := &corev1.ISCSIPersistentVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ISCSIPersistentVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ISCSIVolumeSource(data []byte) {
	m1 := &corev1.ISCSIVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ISCSIVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1KeyToPath(data []byte) {
	m1 := &corev1.KeyToPath{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.KeyToPath{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Lifecycle(data []byte) {
	m1 := &corev1.Lifecycle{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Lifecycle{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1LifecycleHandler(data []byte) {
	m1 := &corev1.LifecycleHandler{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.LifecycleHandler{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1LimitRange(data []byte) {
	m1 := &corev1.LimitRange{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.LimitRange{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1LimitRangeItem(data []byte) {
	m1 := &corev1.LimitRangeItem{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.LimitRangeItem{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1LimitRangeList(data []byte) {
	m1 := &corev1.LimitRangeList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.LimitRangeList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1LimitRangeSpec(data []byte) {
	m1 := &corev1.LimitRangeSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.LimitRangeSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1List(data []byte) {
	m1 := &corev1.List{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.List{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1LoadBalancerIngress(data []byte) {
	m1 := &corev1.LoadBalancerIngress{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.LoadBalancerIngress{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1LoadBalancerStatus(data []byte) {
	m1 := &corev1.LoadBalancerStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.LoadBalancerStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1LocalObjectReference(data []byte) {
	m1 := &corev1.LocalObjectReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.LocalObjectReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1LocalVolumeSource(data []byte) {
	m1 := &corev1.LocalVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.LocalVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NFSVolumeSource(data []byte) {
	m1 := &corev1.NFSVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NFSVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Namespace(data []byte) {
	m1 := &corev1.Namespace{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Namespace{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NamespaceCondition(data []byte) {
	m1 := &corev1.NamespaceCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NamespaceCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NamespaceList(data []byte) {
	m1 := &corev1.NamespaceList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NamespaceList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NamespaceSpec(data []byte) {
	m1 := &corev1.NamespaceSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NamespaceSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NamespaceStatus(data []byte) {
	m1 := &corev1.NamespaceStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NamespaceStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Node(data []byte) {
	m1 := &corev1.Node{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Node{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeAddress(data []byte) {
	m1 := &corev1.NodeAddress{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeAddress{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeAffinity(data []byte) {
	m1 := &corev1.NodeAffinity{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeAffinity{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeCondition(data []byte) {
	m1 := &corev1.NodeCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeConfigSource(data []byte) {
	m1 := &corev1.NodeConfigSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeConfigSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeConfigStatus(data []byte) {
	m1 := &corev1.NodeConfigStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeConfigStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeDaemonEndpoints(data []byte) {
	m1 := &corev1.NodeDaemonEndpoints{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeDaemonEndpoints{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeList(data []byte) {
	m1 := &corev1.NodeList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeProxyOptions(data []byte) {
	m1 := &corev1.NodeProxyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeProxyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeResources(data []byte) {
	m1 := &corev1.NodeResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeSelector(data []byte) {
	m1 := &corev1.NodeSelector{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeSelector{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeSelectorRequirement(data []byte) {
	m1 := &corev1.NodeSelectorRequirement{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeSelectorRequirement{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeSelectorTerm(data []byte) {
	m1 := &corev1.NodeSelectorTerm{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeSelectorTerm{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeSpec(data []byte) {
	m1 := &corev1.NodeSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeStatus(data []byte) {
	m1 := &corev1.NodeStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1NodeSystemInfo(data []byte) {
	m1 := &corev1.NodeSystemInfo{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.NodeSystemInfo{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ObjectFieldSelector(data []byte) {
	m1 := &corev1.ObjectFieldSelector{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ObjectFieldSelector{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ObjectReference(data []byte) {
	m1 := &corev1.ObjectReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ObjectReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolume(data []byte) {
	m1 := &corev1.PersistentVolume{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolume{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolumeClaim(data []byte) {
	m1 := &corev1.PersistentVolumeClaim{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolumeClaim{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolumeClaimCondition(data []byte) {
	m1 := &corev1.PersistentVolumeClaimCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolumeClaimCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolumeClaimList(data []byte) {
	m1 := &corev1.PersistentVolumeClaimList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolumeClaimList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolumeClaimSpec(data []byte) {
	m1 := &corev1.PersistentVolumeClaimSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolumeClaimSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolumeClaimStatus(data []byte) {
	m1 := &corev1.PersistentVolumeClaimStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolumeClaimStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolumeClaimTemplate(data []byte) {
	m1 := &corev1.PersistentVolumeClaimTemplate{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolumeClaimTemplate{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolumeClaimVolumeSource(data []byte) {
	m1 := &corev1.PersistentVolumeClaimVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolumeClaimVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolumeList(data []byte) {
	m1 := &corev1.PersistentVolumeList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolumeList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolumeSource(data []byte) {
	m1 := &corev1.PersistentVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolumeSpec(data []byte) {
	m1 := &corev1.PersistentVolumeSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolumeSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PersistentVolumeStatus(data []byte) {
	m1 := &corev1.PersistentVolumeStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PersistentVolumeStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PhotonPersistentDiskVolumeSource(data []byte) {
	m1 := &corev1.PhotonPersistentDiskVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PhotonPersistentDiskVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Pod(data []byte) {
	m1 := &corev1.Pod{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Pod{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodAffinity(data []byte) {
	m1 := &corev1.PodAffinity{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodAffinity{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodAffinityTerm(data []byte) {
	m1 := &corev1.PodAffinityTerm{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodAffinityTerm{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodAntiAffinity(data []byte) {
	m1 := &corev1.PodAntiAffinity{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodAntiAffinity{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodAttachOptions(data []byte) {
	m1 := &corev1.PodAttachOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodAttachOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodCondition(data []byte) {
	m1 := &corev1.PodCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodDNSConfig(data []byte) {
	m1 := &corev1.PodDNSConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodDNSConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodDNSConfigOption(data []byte) {
	m1 := &corev1.PodDNSConfigOption{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodDNSConfigOption{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodExecOptions(data []byte) {
	m1 := &corev1.PodExecOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodExecOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodIP(data []byte) {
	m1 := &corev1.PodIP{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodIP{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodList(data []byte) {
	m1 := &corev1.PodList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodLogOptions(data []byte) {
	m1 := &corev1.PodLogOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodLogOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodOS(data []byte) {
	m1 := &corev1.PodOS{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodOS{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodPortForwardOptions(data []byte) {
	m1 := &corev1.PodPortForwardOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodPortForwardOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodProxyOptions(data []byte) {
	m1 := &corev1.PodProxyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodProxyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodReadinessGate(data []byte) {
	m1 := &corev1.PodReadinessGate{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodReadinessGate{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodSecurityContext(data []byte) {
	m1 := &corev1.PodSecurityContext{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodSecurityContext{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodSignature(data []byte) {
	m1 := &corev1.PodSignature{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodSignature{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodSpec(data []byte) {
	m1 := &corev1.PodSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodStatus(data []byte) {
	m1 := &corev1.PodStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodStatusResult(data []byte) {
	m1 := &corev1.PodStatusResult{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodStatusResult{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodTemplate(data []byte) {
	m1 := &corev1.PodTemplate{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodTemplate{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodTemplateList(data []byte) {
	m1 := &corev1.PodTemplateList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodTemplateList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PodTemplateSpec(data []byte) {
	m1 := &corev1.PodTemplateSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PodTemplateSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PortStatus(data []byte) {
	m1 := &corev1.PortStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PortStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PortworxVolumeSource(data []byte) {
	m1 := &corev1.PortworxVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PortworxVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Preconditions(data []byte) {
	m1 := &corev1.Preconditions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Preconditions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PreferAvoidPodsEntry(data []byte) {
	m1 := &corev1.PreferAvoidPodsEntry{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PreferAvoidPodsEntry{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1PreferredSchedulingTerm(data []byte) {
	m1 := &corev1.PreferredSchedulingTerm{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.PreferredSchedulingTerm{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Probe(data []byte) {
	m1 := &corev1.Probe{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Probe{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ProbeHandler(data []byte) {
	m1 := &corev1.ProbeHandler{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ProbeHandler{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ProjectedVolumeSource(data []byte) {
	m1 := &corev1.ProjectedVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ProjectedVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1QuobyteVolumeSource(data []byte) {
	m1 := &corev1.QuobyteVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.QuobyteVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1RBDPersistentVolumeSource(data []byte) {
	m1 := &corev1.RBDPersistentVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.RBDPersistentVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1RBDVolumeSource(data []byte) {
	m1 := &corev1.RBDVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.RBDVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1RangeAllocation(data []byte) {
	m1 := &corev1.RangeAllocation{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.RangeAllocation{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ReplicationController(data []byte) {
	m1 := &corev1.ReplicationController{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ReplicationController{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ReplicationControllerCondition(data []byte) {
	m1 := &corev1.ReplicationControllerCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ReplicationControllerCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ReplicationControllerList(data []byte) {
	m1 := &corev1.ReplicationControllerList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ReplicationControllerList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ReplicationControllerSpec(data []byte) {
	m1 := &corev1.ReplicationControllerSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ReplicationControllerSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ReplicationControllerStatus(data []byte) {
	m1 := &corev1.ReplicationControllerStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ReplicationControllerStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ResourceFieldSelector(data []byte) {
	m1 := &corev1.ResourceFieldSelector{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ResourceFieldSelector{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ResourceQuota(data []byte) {
	m1 := &corev1.ResourceQuota{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ResourceQuota{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ResourceQuotaList(data []byte) {
	m1 := &corev1.ResourceQuotaList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ResourceQuotaList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ResourceQuotaSpec(data []byte) {
	m1 := &corev1.ResourceQuotaSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ResourceQuotaSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ResourceQuotaStatus(data []byte) {
	m1 := &corev1.ResourceQuotaStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ResourceQuotaStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ResourceRequirements(data []byte) {
	m1 := &corev1.ResourceRequirements{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ResourceRequirements{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1SELinuxOptions(data []byte) {
	m1 := &corev1.SELinuxOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.SELinuxOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ScaleIOPersistentVolumeSource(data []byte) {
	m1 := &corev1.ScaleIOPersistentVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ScaleIOPersistentVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ScaleIOVolumeSource(data []byte) {
	m1 := &corev1.ScaleIOVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ScaleIOVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ScopeSelector(data []byte) {
	m1 := &corev1.ScopeSelector{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ScopeSelector{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ScopedResourceSelectorRequirement(data []byte) {
	m1 := &corev1.ScopedResourceSelectorRequirement{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ScopedResourceSelectorRequirement{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1SeccompProfile(data []byte) {
	m1 := &corev1.SeccompProfile{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.SeccompProfile{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Secret(data []byte) {
	m1 := &corev1.Secret{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Secret{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1SecretEnvSource(data []byte) {
	m1 := &corev1.SecretEnvSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.SecretEnvSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1SecretKeySelector(data []byte) {
	m1 := &corev1.SecretKeySelector{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.SecretKeySelector{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1SecretList(data []byte) {
	m1 := &corev1.SecretList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.SecretList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1SecretProjection(data []byte) {
	m1 := &corev1.SecretProjection{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.SecretProjection{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1SecretReference(data []byte) {
	m1 := &corev1.SecretReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.SecretReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1SecretVolumeSource(data []byte) {
	m1 := &corev1.SecretVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.SecretVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1SecurityContext(data []byte) {
	m1 := &corev1.SecurityContext{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.SecurityContext{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1SerializedReference(data []byte) {
	m1 := &corev1.SerializedReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.SerializedReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Service(data []byte) {
	m1 := &corev1.Service{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Service{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ServiceAccount(data []byte) {
	m1 := &corev1.ServiceAccount{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ServiceAccount{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ServiceAccountList(data []byte) {
	m1 := &corev1.ServiceAccountList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ServiceAccountList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ServiceAccountTokenProjection(data []byte) {
	m1 := &corev1.ServiceAccountTokenProjection{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ServiceAccountTokenProjection{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ServiceList(data []byte) {
	m1 := &corev1.ServiceList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ServiceList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ServicePort(data []byte) {
	m1 := &corev1.ServicePort{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ServicePort{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ServiceProxyOptions(data []byte) {
	m1 := &corev1.ServiceProxyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ServiceProxyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ServiceSpec(data []byte) {
	m1 := &corev1.ServiceSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ServiceSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1ServiceStatus(data []byte) {
	m1 := &corev1.ServiceStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.ServiceStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1SessionAffinityConfig(data []byte) {
	m1 := &corev1.SessionAffinityConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.SessionAffinityConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1StorageOSPersistentVolumeSource(data []byte) {
	m1 := &corev1.StorageOSPersistentVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.StorageOSPersistentVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1StorageOSVolumeSource(data []byte) {
	m1 := &corev1.StorageOSVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.StorageOSVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Sysctl(data []byte) {
	m1 := &corev1.Sysctl{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Sysctl{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1TCPSocketAction(data []byte) {
	m1 := &corev1.TCPSocketAction{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.TCPSocketAction{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Taint(data []byte) {
	m1 := &corev1.Taint{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Taint{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Toleration(data []byte) {
	m1 := &corev1.Toleration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Toleration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1TopologySelectorLabelRequirement(data []byte) {
	m1 := &corev1.TopologySelectorLabelRequirement{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.TopologySelectorLabelRequirement{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1TopologySelectorTerm(data []byte) {
	m1 := &corev1.TopologySelectorTerm{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.TopologySelectorTerm{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1TopologySpreadConstraint(data []byte) {
	m1 := &corev1.TopologySpreadConstraint{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.TopologySpreadConstraint{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1TypedLocalObjectReference(data []byte) {
	m1 := &corev1.TypedLocalObjectReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.TypedLocalObjectReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1Volume(data []byte) {
	m1 := &corev1.Volume{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.Volume{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1VolumeDevice(data []byte) {
	m1 := &corev1.VolumeDevice{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.VolumeDevice{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1VolumeMount(data []byte) {
	m1 := &corev1.VolumeMount{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.VolumeMount{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1VolumeNodeAffinity(data []byte) {
	m1 := &corev1.VolumeNodeAffinity{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.VolumeNodeAffinity{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1VolumeProjection(data []byte) {
	m1 := &corev1.VolumeProjection{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.VolumeProjection{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1VolumeSource(data []byte) {
	m1 := &corev1.VolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.VolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1VsphereVirtualDiskVolumeSource(data []byte) {
	m1 := &corev1.VsphereVirtualDiskVolumeSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.VsphereVirtualDiskVolumeSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1WeightedPodAffinityTerm(data []byte) {
	m1 := &corev1.WeightedPodAffinityTerm{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.WeightedPodAffinityTerm{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcorev1WindowsSecurityContextOptions(data []byte) {
	m1 := &corev1.WindowsSecurityContextOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &corev1.WindowsSecurityContextOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1Endpoint(data []byte) {
	m1 := &discoveryv1.Endpoint{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1.Endpoint{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1EndpointConditions(data []byte) {
	m1 := &discoveryv1.EndpointConditions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1.EndpointConditions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1EndpointHints(data []byte) {
	m1 := &discoveryv1.EndpointHints{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1.EndpointHints{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1EndpointPort(data []byte) {
	m1 := &discoveryv1.EndpointPort{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1.EndpointPort{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1EndpointSlice(data []byte) {
	m1 := &discoveryv1.EndpointSlice{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1.EndpointSlice{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1EndpointSliceList(data []byte) {
	m1 := &discoveryv1.EndpointSliceList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1.EndpointSliceList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1ForZone(data []byte) {
	m1 := &discoveryv1.ForZone{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1.ForZone{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1beta1Endpoint(data []byte) {
	m1 := &discoveryv1beta1.Endpoint{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1beta1.Endpoint{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1beta1EndpointConditions(data []byte) {
	m1 := &discoveryv1beta1.EndpointConditions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1beta1.EndpointConditions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1beta1EndpointHints(data []byte) {
	m1 := &discoveryv1beta1.EndpointHints{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1beta1.EndpointHints{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1beta1EndpointPort(data []byte) {
	m1 := &discoveryv1beta1.EndpointPort{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1beta1.EndpointPort{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1beta1EndpointSlice(data []byte) {
	m1 := &discoveryv1beta1.EndpointSlice{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1beta1.EndpointSlice{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1beta1EndpointSliceList(data []byte) {
	m1 := &discoveryv1beta1.EndpointSliceList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1beta1.EndpointSliceList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdiscoveryv1beta1ForZone(data []byte) {
	m1 := &discoveryv1beta1.ForZone{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &discoveryv1beta1.ForZone{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzeventsv1Event(data []byte) {
	m1 := &eventsv1.Event{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &eventsv1.Event{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzeventsv1EventList(data []byte) {
	m1 := &eventsv1.EventList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &eventsv1.EventList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzeventsv1EventSeries(data []byte) {
	m1 := &eventsv1.EventSeries{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &eventsv1.EventSeries{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzeventsv1beta1Event(data []byte) {
	m1 := &eventsv1beta1.Event{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &eventsv1beta1.Event{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzeventsv1beta1EventList(data []byte) {
	m1 := &eventsv1beta1.EventList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &eventsv1beta1.EventList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzeventsv1beta1EventSeries(data []byte) {
	m1 := &eventsv1beta1.EventSeries{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &eventsv1beta1.EventSeries{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1AllowedCSIDriver(data []byte) {
	m1 := &extensionsv1beta1.AllowedCSIDriver{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.AllowedCSIDriver{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1AllowedFlexVolume(data []byte) {
	m1 := &extensionsv1beta1.AllowedFlexVolume{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.AllowedFlexVolume{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1AllowedHostPath(data []byte) {
	m1 := &extensionsv1beta1.AllowedHostPath{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.AllowedHostPath{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DaemonSet(data []byte) {
	m1 := &extensionsv1beta1.DaemonSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DaemonSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DaemonSetCondition(data []byte) {
	m1 := &extensionsv1beta1.DaemonSetCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DaemonSetCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DaemonSetList(data []byte) {
	m1 := &extensionsv1beta1.DaemonSetList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DaemonSetList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DaemonSetSpec(data []byte) {
	m1 := &extensionsv1beta1.DaemonSetSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DaemonSetSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DaemonSetStatus(data []byte) {
	m1 := &extensionsv1beta1.DaemonSetStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DaemonSetStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DaemonSetUpdateStrategy(data []byte) {
	m1 := &extensionsv1beta1.DaemonSetUpdateStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DaemonSetUpdateStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1Deployment(data []byte) {
	m1 := &extensionsv1beta1.Deployment{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.Deployment{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DeploymentCondition(data []byte) {
	m1 := &extensionsv1beta1.DeploymentCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DeploymentCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DeploymentList(data []byte) {
	m1 := &extensionsv1beta1.DeploymentList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DeploymentList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DeploymentRollback(data []byte) {
	m1 := &extensionsv1beta1.DeploymentRollback{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DeploymentRollback{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DeploymentSpec(data []byte) {
	m1 := &extensionsv1beta1.DeploymentSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DeploymentSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DeploymentStatus(data []byte) {
	m1 := &extensionsv1beta1.DeploymentStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DeploymentStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1DeploymentStrategy(data []byte) {
	m1 := &extensionsv1beta1.DeploymentStrategy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.DeploymentStrategy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1FSGroupStrategyOptions(data []byte) {
	m1 := &extensionsv1beta1.FSGroupStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.FSGroupStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1HTTPIngressPath(data []byte) {
	m1 := &extensionsv1beta1.HTTPIngressPath{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.HTTPIngressPath{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1HTTPIngressRuleValue(data []byte) {
	m1 := &extensionsv1beta1.HTTPIngressRuleValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.HTTPIngressRuleValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1HostPortRange(data []byte) {
	m1 := &extensionsv1beta1.HostPortRange{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.HostPortRange{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1IDRange(data []byte) {
	m1 := &extensionsv1beta1.IDRange{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.IDRange{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1IPBlock(data []byte) {
	m1 := &extensionsv1beta1.IPBlock{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.IPBlock{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1Ingress(data []byte) {
	m1 := &extensionsv1beta1.Ingress{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.Ingress{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1IngressBackend(data []byte) {
	m1 := &extensionsv1beta1.IngressBackend{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.IngressBackend{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1IngressList(data []byte) {
	m1 := &extensionsv1beta1.IngressList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.IngressList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1IngressRule(data []byte) {
	m1 := &extensionsv1beta1.IngressRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.IngressRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1IngressRuleValue(data []byte) {
	m1 := &extensionsv1beta1.IngressRuleValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.IngressRuleValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1IngressSpec(data []byte) {
	m1 := &extensionsv1beta1.IngressSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.IngressSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1IngressStatus(data []byte) {
	m1 := &extensionsv1beta1.IngressStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.IngressStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1IngressTLS(data []byte) {
	m1 := &extensionsv1beta1.IngressTLS{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.IngressTLS{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1NetworkPolicy(data []byte) {
	m1 := &extensionsv1beta1.NetworkPolicy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.NetworkPolicy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1NetworkPolicyEgressRule(data []byte) {
	m1 := &extensionsv1beta1.NetworkPolicyEgressRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.NetworkPolicyEgressRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1NetworkPolicyIngressRule(data []byte) {
	m1 := &extensionsv1beta1.NetworkPolicyIngressRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.NetworkPolicyIngressRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1NetworkPolicyList(data []byte) {
	m1 := &extensionsv1beta1.NetworkPolicyList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.NetworkPolicyList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1NetworkPolicyPeer(data []byte) {
	m1 := &extensionsv1beta1.NetworkPolicyPeer{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.NetworkPolicyPeer{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1NetworkPolicyPort(data []byte) {
	m1 := &extensionsv1beta1.NetworkPolicyPort{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.NetworkPolicyPort{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1NetworkPolicySpec(data []byte) {
	m1 := &extensionsv1beta1.NetworkPolicySpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.NetworkPolicySpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1NetworkPolicyStatus(data []byte) {
	m1 := &extensionsv1beta1.NetworkPolicyStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.NetworkPolicyStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1PodSecurityPolicy(data []byte) {
	m1 := &extensionsv1beta1.PodSecurityPolicy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.PodSecurityPolicy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1PodSecurityPolicyList(data []byte) {
	m1 := &extensionsv1beta1.PodSecurityPolicyList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.PodSecurityPolicyList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1PodSecurityPolicySpec(data []byte) {
	m1 := &extensionsv1beta1.PodSecurityPolicySpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.PodSecurityPolicySpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1ReplicaSet(data []byte) {
	m1 := &extensionsv1beta1.ReplicaSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.ReplicaSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1ReplicaSetCondition(data []byte) {
	m1 := &extensionsv1beta1.ReplicaSetCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.ReplicaSetCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1ReplicaSetList(data []byte) {
	m1 := &extensionsv1beta1.ReplicaSetList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.ReplicaSetList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1ReplicaSetSpec(data []byte) {
	m1 := &extensionsv1beta1.ReplicaSetSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.ReplicaSetSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1ReplicaSetStatus(data []byte) {
	m1 := &extensionsv1beta1.ReplicaSetStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.ReplicaSetStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1RollbackConfig(data []byte) {
	m1 := &extensionsv1beta1.RollbackConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.RollbackConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1RollingUpdateDaemonSet(data []byte) {
	m1 := &extensionsv1beta1.RollingUpdateDaemonSet{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.RollingUpdateDaemonSet{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1RollingUpdateDeployment(data []byte) {
	m1 := &extensionsv1beta1.RollingUpdateDeployment{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.RollingUpdateDeployment{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1RunAsGroupStrategyOptions(data []byte) {
	m1 := &extensionsv1beta1.RunAsGroupStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.RunAsGroupStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1RunAsUserStrategyOptions(data []byte) {
	m1 := &extensionsv1beta1.RunAsUserStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.RunAsUserStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1RuntimeClassStrategyOptions(data []byte) {
	m1 := &extensionsv1beta1.RuntimeClassStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.RuntimeClassStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1SELinuxStrategyOptions(data []byte) {
	m1 := &extensionsv1beta1.SELinuxStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.SELinuxStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1Scale(data []byte) {
	m1 := &extensionsv1beta1.Scale{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.Scale{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1ScaleSpec(data []byte) {
	m1 := &extensionsv1beta1.ScaleSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.ScaleSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1ScaleStatus(data []byte) {
	m1 := &extensionsv1beta1.ScaleStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.ScaleStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzextensionsv1beta1SupplementalGroupsStrategyOptions(data []byte) {
	m1 := &extensionsv1beta1.SupplementalGroupsStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &extensionsv1beta1.SupplementalGroupsStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1FlowDistinguisherMethod(data []byte) {
	m1 := &flowcontrolv1alpha1.FlowDistinguisherMethod{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.FlowDistinguisherMethod{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1FlowSchema(data []byte) {
	m1 := &flowcontrolv1alpha1.FlowSchema{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.FlowSchema{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1FlowSchemaCondition(data []byte) {
	m1 := &flowcontrolv1alpha1.FlowSchemaCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.FlowSchemaCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1FlowSchemaList(data []byte) {
	m1 := &flowcontrolv1alpha1.FlowSchemaList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.FlowSchemaList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1FlowSchemaSpec(data []byte) {
	m1 := &flowcontrolv1alpha1.FlowSchemaSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.FlowSchemaSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1FlowSchemaStatus(data []byte) {
	m1 := &flowcontrolv1alpha1.FlowSchemaStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.FlowSchemaStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1GroupSubject(data []byte) {
	m1 := &flowcontrolv1alpha1.GroupSubject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.GroupSubject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1LimitResponse(data []byte) {
	m1 := &flowcontrolv1alpha1.LimitResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.LimitResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1LimitedPriorityLevelConfiguration(data []byte) {
	m1 := &flowcontrolv1alpha1.LimitedPriorityLevelConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.LimitedPriorityLevelConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1NonResourcePolicyRule(data []byte) {
	m1 := &flowcontrolv1alpha1.NonResourcePolicyRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.NonResourcePolicyRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1PolicyRulesWithSubjects(data []byte) {
	m1 := &flowcontrolv1alpha1.PolicyRulesWithSubjects{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.PolicyRulesWithSubjects{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1PriorityLevelConfiguration(data []byte) {
	m1 := &flowcontrolv1alpha1.PriorityLevelConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.PriorityLevelConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1PriorityLevelConfigurationCondition(data []byte) {
	m1 := &flowcontrolv1alpha1.PriorityLevelConfigurationCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.PriorityLevelConfigurationCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1PriorityLevelConfigurationList(data []byte) {
	m1 := &flowcontrolv1alpha1.PriorityLevelConfigurationList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.PriorityLevelConfigurationList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1PriorityLevelConfigurationReference(data []byte) {
	m1 := &flowcontrolv1alpha1.PriorityLevelConfigurationReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.PriorityLevelConfigurationReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1PriorityLevelConfigurationSpec(data []byte) {
	m1 := &flowcontrolv1alpha1.PriorityLevelConfigurationSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.PriorityLevelConfigurationSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1PriorityLevelConfigurationStatus(data []byte) {
	m1 := &flowcontrolv1alpha1.PriorityLevelConfigurationStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.PriorityLevelConfigurationStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1QueuingConfiguration(data []byte) {
	m1 := &flowcontrolv1alpha1.QueuingConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.QueuingConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1ResourcePolicyRule(data []byte) {
	m1 := &flowcontrolv1alpha1.ResourcePolicyRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.ResourcePolicyRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1ServiceAccountSubject(data []byte) {
	m1 := &flowcontrolv1alpha1.ServiceAccountSubject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.ServiceAccountSubject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1Subject(data []byte) {
	m1 := &flowcontrolv1alpha1.Subject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.Subject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1alpha1UserSubject(data []byte) {
	m1 := &flowcontrolv1alpha1.UserSubject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1alpha1.UserSubject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1FlowDistinguisherMethod(data []byte) {
	m1 := &flowcontrolv1beta1.FlowDistinguisherMethod{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.FlowDistinguisherMethod{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1FlowSchema(data []byte) {
	m1 := &flowcontrolv1beta1.FlowSchema{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.FlowSchema{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1FlowSchemaCondition(data []byte) {
	m1 := &flowcontrolv1beta1.FlowSchemaCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.FlowSchemaCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1FlowSchemaList(data []byte) {
	m1 := &flowcontrolv1beta1.FlowSchemaList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.FlowSchemaList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1FlowSchemaSpec(data []byte) {
	m1 := &flowcontrolv1beta1.FlowSchemaSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.FlowSchemaSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1FlowSchemaStatus(data []byte) {
	m1 := &flowcontrolv1beta1.FlowSchemaStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.FlowSchemaStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1GroupSubject(data []byte) {
	m1 := &flowcontrolv1beta1.GroupSubject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.GroupSubject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1LimitResponse(data []byte) {
	m1 := &flowcontrolv1beta1.LimitResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.LimitResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1LimitedPriorityLevelConfiguration(data []byte) {
	m1 := &flowcontrolv1beta1.LimitedPriorityLevelConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.LimitedPriorityLevelConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1NonResourcePolicyRule(data []byte) {
	m1 := &flowcontrolv1beta1.NonResourcePolicyRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.NonResourcePolicyRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1PolicyRulesWithSubjects(data []byte) {
	m1 := &flowcontrolv1beta1.PolicyRulesWithSubjects{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.PolicyRulesWithSubjects{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1PriorityLevelConfiguration(data []byte) {
	m1 := &flowcontrolv1beta1.PriorityLevelConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.PriorityLevelConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1PriorityLevelConfigurationCondition(data []byte) {
	m1 := &flowcontrolv1beta1.PriorityLevelConfigurationCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.PriorityLevelConfigurationCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1PriorityLevelConfigurationList(data []byte) {
	m1 := &flowcontrolv1beta1.PriorityLevelConfigurationList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.PriorityLevelConfigurationList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1PriorityLevelConfigurationReference(data []byte) {
	m1 := &flowcontrolv1beta1.PriorityLevelConfigurationReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.PriorityLevelConfigurationReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1PriorityLevelConfigurationSpec(data []byte) {
	m1 := &flowcontrolv1beta1.PriorityLevelConfigurationSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.PriorityLevelConfigurationSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1PriorityLevelConfigurationStatus(data []byte) {
	m1 := &flowcontrolv1beta1.PriorityLevelConfigurationStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.PriorityLevelConfigurationStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1QueuingConfiguration(data []byte) {
	m1 := &flowcontrolv1beta1.QueuingConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.QueuingConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1ResourcePolicyRule(data []byte) {
	m1 := &flowcontrolv1beta1.ResourcePolicyRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.ResourcePolicyRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1ServiceAccountSubject(data []byte) {
	m1 := &flowcontrolv1beta1.ServiceAccountSubject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.ServiceAccountSubject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1Subject(data []byte) {
	m1 := &flowcontrolv1beta1.Subject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.Subject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta1UserSubject(data []byte) {
	m1 := &flowcontrolv1beta1.UserSubject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta1.UserSubject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2FlowDistinguisherMethod(data []byte) {
	m1 := &flowcontrolv1beta2.FlowDistinguisherMethod{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.FlowDistinguisherMethod{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2FlowSchema(data []byte) {
	m1 := &flowcontrolv1beta2.FlowSchema{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.FlowSchema{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2FlowSchemaCondition(data []byte) {
	m1 := &flowcontrolv1beta2.FlowSchemaCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.FlowSchemaCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2FlowSchemaList(data []byte) {
	m1 := &flowcontrolv1beta2.FlowSchemaList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.FlowSchemaList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2FlowSchemaSpec(data []byte) {
	m1 := &flowcontrolv1beta2.FlowSchemaSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.FlowSchemaSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2FlowSchemaStatus(data []byte) {
	m1 := &flowcontrolv1beta2.FlowSchemaStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.FlowSchemaStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2GroupSubject(data []byte) {
	m1 := &flowcontrolv1beta2.GroupSubject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.GroupSubject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2LimitResponse(data []byte) {
	m1 := &flowcontrolv1beta2.LimitResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.LimitResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2LimitedPriorityLevelConfiguration(data []byte) {
	m1 := &flowcontrolv1beta2.LimitedPriorityLevelConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.LimitedPriorityLevelConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2NonResourcePolicyRule(data []byte) {
	m1 := &flowcontrolv1beta2.NonResourcePolicyRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.NonResourcePolicyRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2PolicyRulesWithSubjects(data []byte) {
	m1 := &flowcontrolv1beta2.PolicyRulesWithSubjects{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.PolicyRulesWithSubjects{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2PriorityLevelConfiguration(data []byte) {
	m1 := &flowcontrolv1beta2.PriorityLevelConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.PriorityLevelConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2PriorityLevelConfigurationCondition(data []byte) {
	m1 := &flowcontrolv1beta2.PriorityLevelConfigurationCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.PriorityLevelConfigurationCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2PriorityLevelConfigurationList(data []byte) {
	m1 := &flowcontrolv1beta2.PriorityLevelConfigurationList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.PriorityLevelConfigurationList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2PriorityLevelConfigurationReference(data []byte) {
	m1 := &flowcontrolv1beta2.PriorityLevelConfigurationReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.PriorityLevelConfigurationReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2PriorityLevelConfigurationSpec(data []byte) {
	m1 := &flowcontrolv1beta2.PriorityLevelConfigurationSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.PriorityLevelConfigurationSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2PriorityLevelConfigurationStatus(data []byte) {
	m1 := &flowcontrolv1beta2.PriorityLevelConfigurationStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.PriorityLevelConfigurationStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2QueuingConfiguration(data []byte) {
	m1 := &flowcontrolv1beta2.QueuingConfiguration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.QueuingConfiguration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2ResourcePolicyRule(data []byte) {
	m1 := &flowcontrolv1beta2.ResourcePolicyRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.ResourcePolicyRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2ServiceAccountSubject(data []byte) {
	m1 := &flowcontrolv1beta2.ServiceAccountSubject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.ServiceAccountSubject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2Subject(data []byte) {
	m1 := &flowcontrolv1beta2.Subject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.Subject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzflowcontrolv1beta2UserSubject(data []byte) {
	m1 := &flowcontrolv1beta2.UserSubject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &flowcontrolv1beta2.UserSubject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzimagepolicyv1alpha1ImageReview(data []byte) {
	m1 := &imagepolicyv1alpha1.ImageReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &imagepolicyv1alpha1.ImageReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzimagepolicyv1alpha1ImageReviewContainerSpec(data []byte) {
	m1 := &imagepolicyv1alpha1.ImageReviewContainerSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &imagepolicyv1alpha1.ImageReviewContainerSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzimagepolicyv1alpha1ImageReviewSpec(data []byte) {
	m1 := &imagepolicyv1alpha1.ImageReviewSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &imagepolicyv1alpha1.ImageReviewSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzimagepolicyv1alpha1ImageReviewStatus(data []byte) {
	m1 := &imagepolicyv1alpha1.ImageReviewStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &imagepolicyv1alpha1.ImageReviewStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1HTTPIngressPath(data []byte) {
	m1 := &networkingv1.HTTPIngressPath{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.HTTPIngressPath{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1HTTPIngressRuleValue(data []byte) {
	m1 := &networkingv1.HTTPIngressRuleValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.HTTPIngressRuleValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IPBlock(data []byte) {
	m1 := &networkingv1.IPBlock{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IPBlock{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1Ingress(data []byte) {
	m1 := &networkingv1.Ingress{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.Ingress{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressBackend(data []byte) {
	m1 := &networkingv1.IngressBackend{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressBackend{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressClass(data []byte) {
	m1 := &networkingv1.IngressClass{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressClass{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressClassList(data []byte) {
	m1 := &networkingv1.IngressClassList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressClassList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressClassParametersReference(data []byte) {
	m1 := &networkingv1.IngressClassParametersReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressClassParametersReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressClassSpec(data []byte) {
	m1 := &networkingv1.IngressClassSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressClassSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressList(data []byte) {
	m1 := &networkingv1.IngressList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressRule(data []byte) {
	m1 := &networkingv1.IngressRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressRuleValue(data []byte) {
	m1 := &networkingv1.IngressRuleValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressRuleValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressServiceBackend(data []byte) {
	m1 := &networkingv1.IngressServiceBackend{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressServiceBackend{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressSpec(data []byte) {
	m1 := &networkingv1.IngressSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressStatus(data []byte) {
	m1 := &networkingv1.IngressStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1IngressTLS(data []byte) {
	m1 := &networkingv1.IngressTLS{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.IngressTLS{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1NetworkPolicy(data []byte) {
	m1 := &networkingv1.NetworkPolicy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.NetworkPolicy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1NetworkPolicyEgressRule(data []byte) {
	m1 := &networkingv1.NetworkPolicyEgressRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.NetworkPolicyEgressRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1NetworkPolicyIngressRule(data []byte) {
	m1 := &networkingv1.NetworkPolicyIngressRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.NetworkPolicyIngressRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1NetworkPolicyList(data []byte) {
	m1 := &networkingv1.NetworkPolicyList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.NetworkPolicyList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1NetworkPolicyPeer(data []byte) {
	m1 := &networkingv1.NetworkPolicyPeer{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.NetworkPolicyPeer{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1NetworkPolicyPort(data []byte) {
	m1 := &networkingv1.NetworkPolicyPort{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.NetworkPolicyPort{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1NetworkPolicySpec(data []byte) {
	m1 := &networkingv1.NetworkPolicySpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.NetworkPolicySpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1NetworkPolicyStatus(data []byte) {
	m1 := &networkingv1.NetworkPolicyStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.NetworkPolicyStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1ServiceBackendPort(data []byte) {
	m1 := &networkingv1.ServiceBackendPort{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1.ServiceBackendPort{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1HTTPIngressPath(data []byte) {
	m1 := &networkingv1beta1.HTTPIngressPath{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.HTTPIngressPath{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1HTTPIngressRuleValue(data []byte) {
	m1 := &networkingv1beta1.HTTPIngressRuleValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.HTTPIngressRuleValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1Ingress(data []byte) {
	m1 := &networkingv1beta1.Ingress{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.Ingress{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1IngressBackend(data []byte) {
	m1 := &networkingv1beta1.IngressBackend{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.IngressBackend{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1IngressClass(data []byte) {
	m1 := &networkingv1beta1.IngressClass{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.IngressClass{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1IngressClassList(data []byte) {
	m1 := &networkingv1beta1.IngressClassList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.IngressClassList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1IngressClassParametersReference(data []byte) {
	m1 := &networkingv1beta1.IngressClassParametersReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.IngressClassParametersReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1IngressClassSpec(data []byte) {
	m1 := &networkingv1beta1.IngressClassSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.IngressClassSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1IngressList(data []byte) {
	m1 := &networkingv1beta1.IngressList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.IngressList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1IngressRule(data []byte) {
	m1 := &networkingv1beta1.IngressRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.IngressRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1IngressRuleValue(data []byte) {
	m1 := &networkingv1beta1.IngressRuleValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.IngressRuleValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1IngressSpec(data []byte) {
	m1 := &networkingv1beta1.IngressSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.IngressSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1IngressStatus(data []byte) {
	m1 := &networkingv1beta1.IngressStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.IngressStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznetworkingv1beta1IngressTLS(data []byte) {
	m1 := &networkingv1beta1.IngressTLS{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &networkingv1beta1.IngressTLS{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1Overhead(data []byte) {
	m1 := &nodev1.Overhead{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1.Overhead{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1RuntimeClass(data []byte) {
	m1 := &nodev1.RuntimeClass{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1.RuntimeClass{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1RuntimeClassList(data []byte) {
	m1 := &nodev1.RuntimeClassList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1.RuntimeClassList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1Scheduling(data []byte) {
	m1 := &nodev1.Scheduling{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1.Scheduling{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1alpha1Overhead(data []byte) {
	m1 := &nodev1alpha1.Overhead{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1alpha1.Overhead{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1alpha1RuntimeClass(data []byte) {
	m1 := &nodev1alpha1.RuntimeClass{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1alpha1.RuntimeClass{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1alpha1RuntimeClassList(data []byte) {
	m1 := &nodev1alpha1.RuntimeClassList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1alpha1.RuntimeClassList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1alpha1RuntimeClassSpec(data []byte) {
	m1 := &nodev1alpha1.RuntimeClassSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1alpha1.RuntimeClassSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1alpha1Scheduling(data []byte) {
	m1 := &nodev1alpha1.Scheduling{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1alpha1.Scheduling{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1beta1Overhead(data []byte) {
	m1 := &nodev1beta1.Overhead{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1beta1.Overhead{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1beta1RuntimeClass(data []byte) {
	m1 := &nodev1beta1.RuntimeClass{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1beta1.RuntimeClass{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1beta1RuntimeClassList(data []byte) {
	m1 := &nodev1beta1.RuntimeClassList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1beta1.RuntimeClassList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzznodev1beta1Scheduling(data []byte) {
	m1 := &nodev1beta1.Scheduling{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &nodev1beta1.Scheduling{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1Eviction(data []byte) {
	m1 := &policyv1.Eviction{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1.Eviction{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1PodDisruptionBudget(data []byte) {
	m1 := &policyv1.PodDisruptionBudget{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1.PodDisruptionBudget{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1PodDisruptionBudgetList(data []byte) {
	m1 := &policyv1.PodDisruptionBudgetList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1.PodDisruptionBudgetList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1PodDisruptionBudgetSpec(data []byte) {
	m1 := &policyv1.PodDisruptionBudgetSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1.PodDisruptionBudgetSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1PodDisruptionBudgetStatus(data []byte) {
	m1 := &policyv1.PodDisruptionBudgetStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1.PodDisruptionBudgetStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1AllowedCSIDriver(data []byte) {
	m1 := &policyv1beta1.AllowedCSIDriver{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.AllowedCSIDriver{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1AllowedFlexVolume(data []byte) {
	m1 := &policyv1beta1.AllowedFlexVolume{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.AllowedFlexVolume{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1AllowedHostPath(data []byte) {
	m1 := &policyv1beta1.AllowedHostPath{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.AllowedHostPath{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1Eviction(data []byte) {
	m1 := &policyv1beta1.Eviction{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.Eviction{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1FSGroupStrategyOptions(data []byte) {
	m1 := &policyv1beta1.FSGroupStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.FSGroupStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1HostPortRange(data []byte) {
	m1 := &policyv1beta1.HostPortRange{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.HostPortRange{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1IDRange(data []byte) {
	m1 := &policyv1beta1.IDRange{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.IDRange{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1PodDisruptionBudget(data []byte) {
	m1 := &policyv1beta1.PodDisruptionBudget{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.PodDisruptionBudget{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1PodDisruptionBudgetList(data []byte) {
	m1 := &policyv1beta1.PodDisruptionBudgetList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.PodDisruptionBudgetList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1PodDisruptionBudgetSpec(data []byte) {
	m1 := &policyv1beta1.PodDisruptionBudgetSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.PodDisruptionBudgetSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1PodDisruptionBudgetStatus(data []byte) {
	m1 := &policyv1beta1.PodDisruptionBudgetStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.PodDisruptionBudgetStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1PodSecurityPolicy(data []byte) {
	m1 := &policyv1beta1.PodSecurityPolicy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.PodSecurityPolicy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1PodSecurityPolicyList(data []byte) {
	m1 := &policyv1beta1.PodSecurityPolicyList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.PodSecurityPolicyList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1PodSecurityPolicySpec(data []byte) {
	m1 := &policyv1beta1.PodSecurityPolicySpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.PodSecurityPolicySpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1RunAsGroupStrategyOptions(data []byte) {
	m1 := &policyv1beta1.RunAsGroupStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.RunAsGroupStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1RunAsUserStrategyOptions(data []byte) {
	m1 := &policyv1beta1.RunAsUserStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.RunAsUserStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1RuntimeClassStrategyOptions(data []byte) {
	m1 := &policyv1beta1.RuntimeClassStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.RuntimeClassStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1SELinuxStrategyOptions(data []byte) {
	m1 := &policyv1beta1.SELinuxStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.SELinuxStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpolicyv1beta1SupplementalGroupsStrategyOptions(data []byte) {
	m1 := &policyv1beta1.SupplementalGroupsStrategyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &policyv1beta1.SupplementalGroupsStrategyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1AggregationRule(data []byte) {
	m1 := &rbacv1.AggregationRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.AggregationRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1ClusterRole(data []byte) {
	m1 := &rbacv1.ClusterRole{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.ClusterRole{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1ClusterRoleBinding(data []byte) {
	m1 := &rbacv1.ClusterRoleBinding{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.ClusterRoleBinding{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1ClusterRoleBindingList(data []byte) {
	m1 := &rbacv1.ClusterRoleBindingList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.ClusterRoleBindingList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1ClusterRoleList(data []byte) {
	m1 := &rbacv1.ClusterRoleList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.ClusterRoleList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1PolicyRule(data []byte) {
	m1 := &rbacv1.PolicyRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.PolicyRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1Role(data []byte) {
	m1 := &rbacv1.Role{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.Role{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1RoleBinding(data []byte) {
	m1 := &rbacv1.RoleBinding{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.RoleBinding{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1RoleBindingList(data []byte) {
	m1 := &rbacv1.RoleBindingList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.RoleBindingList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1RoleList(data []byte) {
	m1 := &rbacv1.RoleList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.RoleList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1RoleRef(data []byte) {
	m1 := &rbacv1.RoleRef{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.RoleRef{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1Subject(data []byte) {
	m1 := &rbacv1.Subject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1.Subject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1AggregationRule(data []byte) {
	m1 := &rbacv1alpha1.AggregationRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.AggregationRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1ClusterRole(data []byte) {
	m1 := &rbacv1alpha1.ClusterRole{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.ClusterRole{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1ClusterRoleBinding(data []byte) {
	m1 := &rbacv1alpha1.ClusterRoleBinding{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.ClusterRoleBinding{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1ClusterRoleBindingList(data []byte) {
	m1 := &rbacv1alpha1.ClusterRoleBindingList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.ClusterRoleBindingList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1ClusterRoleList(data []byte) {
	m1 := &rbacv1alpha1.ClusterRoleList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.ClusterRoleList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1PolicyRule(data []byte) {
	m1 := &rbacv1alpha1.PolicyRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.PolicyRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1Role(data []byte) {
	m1 := &rbacv1alpha1.Role{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.Role{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1RoleBinding(data []byte) {
	m1 := &rbacv1alpha1.RoleBinding{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.RoleBinding{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1RoleBindingList(data []byte) {
	m1 := &rbacv1alpha1.RoleBindingList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.RoleBindingList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1RoleList(data []byte) {
	m1 := &rbacv1alpha1.RoleList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.RoleList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1RoleRef(data []byte) {
	m1 := &rbacv1alpha1.RoleRef{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.RoleRef{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1alpha1Subject(data []byte) {
	m1 := &rbacv1alpha1.Subject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1alpha1.Subject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1AggregationRule(data []byte) {
	m1 := &rbacv1beta1.AggregationRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.AggregationRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1ClusterRole(data []byte) {
	m1 := &rbacv1beta1.ClusterRole{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.ClusterRole{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1ClusterRoleBinding(data []byte) {
	m1 := &rbacv1beta1.ClusterRoleBinding{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.ClusterRoleBinding{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1ClusterRoleBindingList(data []byte) {
	m1 := &rbacv1beta1.ClusterRoleBindingList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.ClusterRoleBindingList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1ClusterRoleList(data []byte) {
	m1 := &rbacv1beta1.ClusterRoleList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.ClusterRoleList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1PolicyRule(data []byte) {
	m1 := &rbacv1beta1.PolicyRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.PolicyRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1Role(data []byte) {
	m1 := &rbacv1beta1.Role{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.Role{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1RoleBinding(data []byte) {
	m1 := &rbacv1beta1.RoleBinding{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.RoleBinding{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1RoleBindingList(data []byte) {
	m1 := &rbacv1beta1.RoleBindingList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.RoleBindingList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1RoleList(data []byte) {
	m1 := &rbacv1beta1.RoleList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.RoleList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1RoleRef(data []byte) {
	m1 := &rbacv1beta1.RoleRef{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.RoleRef{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzrbacv1beta1Subject(data []byte) {
	m1 := &rbacv1beta1.Subject{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &rbacv1beta1.Subject{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzschedulingv1PriorityClass(data []byte) {
	m1 := &schedulingv1.PriorityClass{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &schedulingv1.PriorityClass{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzschedulingv1PriorityClassList(data []byte) {
	m1 := &schedulingv1.PriorityClassList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &schedulingv1.PriorityClassList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzschedulingv1alpha1PriorityClass(data []byte) {
	m1 := &schedulingv1alpha1.PriorityClass{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &schedulingv1alpha1.PriorityClass{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzschedulingv1alpha1PriorityClassList(data []byte) {
	m1 := &schedulingv1alpha1.PriorityClassList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &schedulingv1alpha1.PriorityClassList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzschedulingv1beta1PriorityClass(data []byte) {
	m1 := &schedulingv1beta1.PriorityClass{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &schedulingv1beta1.PriorityClass{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzschedulingv1beta1PriorityClassList(data []byte) {
	m1 := &schedulingv1beta1.PriorityClassList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &schedulingv1beta1.PriorityClassList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1CSIDriver(data []byte) {
	m1 := &storagev1.CSIDriver{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.CSIDriver{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1CSIDriverList(data []byte) {
	m1 := &storagev1.CSIDriverList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.CSIDriverList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1CSIDriverSpec(data []byte) {
	m1 := &storagev1.CSIDriverSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.CSIDriverSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1CSINode(data []byte) {
	m1 := &storagev1.CSINode{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.CSINode{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1CSINodeDriver(data []byte) {
	m1 := &storagev1.CSINodeDriver{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.CSINodeDriver{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1CSINodeList(data []byte) {
	m1 := &storagev1.CSINodeList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.CSINodeList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1CSINodeSpec(data []byte) {
	m1 := &storagev1.CSINodeSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.CSINodeSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1CSIStorageCapacity(data []byte) {
	m1 := &storagev1.CSIStorageCapacity{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.CSIStorageCapacity{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1CSIStorageCapacityList(data []byte) {
	m1 := &storagev1.CSIStorageCapacityList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.CSIStorageCapacityList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1StorageClass(data []byte) {
	m1 := &storagev1.StorageClass{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.StorageClass{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1StorageClassList(data []byte) {
	m1 := &storagev1.StorageClassList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.StorageClassList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1TokenRequest(data []byte) {
	m1 := &storagev1.TokenRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.TokenRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1VolumeAttachment(data []byte) {
	m1 := &storagev1.VolumeAttachment{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.VolumeAttachment{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1VolumeAttachmentList(data []byte) {
	m1 := &storagev1.VolumeAttachmentList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.VolumeAttachmentList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1VolumeAttachmentSource(data []byte) {
	m1 := &storagev1.VolumeAttachmentSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.VolumeAttachmentSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1VolumeAttachmentSpec(data []byte) {
	m1 := &storagev1.VolumeAttachmentSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.VolumeAttachmentSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1VolumeAttachmentStatus(data []byte) {
	m1 := &storagev1.VolumeAttachmentStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.VolumeAttachmentStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1VolumeError(data []byte) {
	m1 := &storagev1.VolumeError{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.VolumeError{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1VolumeNodeResources(data []byte) {
	m1 := &storagev1.VolumeNodeResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1.VolumeNodeResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1alpha1CSIStorageCapacity(data []byte) {
	m1 := &storagev1alpha1.CSIStorageCapacity{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1alpha1.CSIStorageCapacity{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1alpha1CSIStorageCapacityList(data []byte) {
	m1 := &storagev1alpha1.CSIStorageCapacityList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1alpha1.CSIStorageCapacityList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1alpha1VolumeAttachment(data []byte) {
	m1 := &storagev1alpha1.VolumeAttachment{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1alpha1.VolumeAttachment{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1alpha1VolumeAttachmentList(data []byte) {
	m1 := &storagev1alpha1.VolumeAttachmentList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1alpha1.VolumeAttachmentList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1alpha1VolumeAttachmentSource(data []byte) {
	m1 := &storagev1alpha1.VolumeAttachmentSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1alpha1.VolumeAttachmentSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1alpha1VolumeAttachmentSpec(data []byte) {
	m1 := &storagev1alpha1.VolumeAttachmentSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1alpha1.VolumeAttachmentSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1alpha1VolumeAttachmentStatus(data []byte) {
	m1 := &storagev1alpha1.VolumeAttachmentStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1alpha1.VolumeAttachmentStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1alpha1VolumeError(data []byte) {
	m1 := &storagev1alpha1.VolumeError{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1alpha1.VolumeError{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1CSIDriver(data []byte) {
	m1 := &storagev1beta1.CSIDriver{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.CSIDriver{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1CSIDriverList(data []byte) {
	m1 := &storagev1beta1.CSIDriverList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.CSIDriverList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1CSIDriverSpec(data []byte) {
	m1 := &storagev1beta1.CSIDriverSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.CSIDriverSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1CSINode(data []byte) {
	m1 := &storagev1beta1.CSINode{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.CSINode{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1CSINodeDriver(data []byte) {
	m1 := &storagev1beta1.CSINodeDriver{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.CSINodeDriver{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1CSINodeList(data []byte) {
	m1 := &storagev1beta1.CSINodeList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.CSINodeList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1CSINodeSpec(data []byte) {
	m1 := &storagev1beta1.CSINodeSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.CSINodeSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1CSIStorageCapacity(data []byte) {
	m1 := &storagev1beta1.CSIStorageCapacity{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.CSIStorageCapacity{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1CSIStorageCapacityList(data []byte) {
	m1 := &storagev1beta1.CSIStorageCapacityList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.CSIStorageCapacityList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1StorageClass(data []byte) {
	m1 := &storagev1beta1.StorageClass{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.StorageClass{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1StorageClassList(data []byte) {
	m1 := &storagev1beta1.StorageClassList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.StorageClassList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1TokenRequest(data []byte) {
	m1 := &storagev1beta1.TokenRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.TokenRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1VolumeAttachment(data []byte) {
	m1 := &storagev1beta1.VolumeAttachment{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.VolumeAttachment{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1VolumeAttachmentList(data []byte) {
	m1 := &storagev1beta1.VolumeAttachmentList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.VolumeAttachmentList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1VolumeAttachmentSource(data []byte) {
	m1 := &storagev1beta1.VolumeAttachmentSource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.VolumeAttachmentSource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1VolumeAttachmentSpec(data []byte) {
	m1 := &storagev1beta1.VolumeAttachmentSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.VolumeAttachmentSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1VolumeAttachmentStatus(data []byte) {
	m1 := &storagev1beta1.VolumeAttachmentStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.VolumeAttachmentStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1VolumeError(data []byte) {
	m1 := &storagev1beta1.VolumeError{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.VolumeError{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzstoragev1beta1VolumeNodeResources(data []byte) {
	m1 := &storagev1beta1.VolumeNodeResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &storagev1beta1.VolumeNodeResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1ConversionRequest(data []byte) {
	m1 := &apiextensionsv1.ConversionRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.ConversionRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1ConversionResponse(data []byte) {
	m1 := &apiextensionsv1.ConversionResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.ConversionResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1ConversionReview(data []byte) {
	m1 := &apiextensionsv1.ConversionReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.ConversionReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceColumnDefinition(data []byte) {
	m1 := &apiextensionsv1.CustomResourceColumnDefinition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceColumnDefinition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceConversion(data []byte) {
	m1 := &apiextensionsv1.CustomResourceConversion{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceConversion{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceDefinition(data []byte) {
	m1 := &apiextensionsv1.CustomResourceDefinition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceDefinition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceDefinitionCondition(data []byte) {
	m1 := &apiextensionsv1.CustomResourceDefinitionCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceDefinitionCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceDefinitionList(data []byte) {
	m1 := &apiextensionsv1.CustomResourceDefinitionList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceDefinitionList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceDefinitionNames(data []byte) {
	m1 := &apiextensionsv1.CustomResourceDefinitionNames{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceDefinitionNames{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceDefinitionSpec(data []byte) {
	m1 := &apiextensionsv1.CustomResourceDefinitionSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceDefinitionSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceDefinitionStatus(data []byte) {
	m1 := &apiextensionsv1.CustomResourceDefinitionStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceDefinitionStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceDefinitionVersion(data []byte) {
	m1 := &apiextensionsv1.CustomResourceDefinitionVersion{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceDefinitionVersion{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceSubresourceScale(data []byte) {
	m1 := &apiextensionsv1.CustomResourceSubresourceScale{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceSubresourceScale{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceSubresourceStatus(data []byte) {
	m1 := &apiextensionsv1.CustomResourceSubresourceStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceSubresourceStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceSubresources(data []byte) {
	m1 := &apiextensionsv1.CustomResourceSubresources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceSubresources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1CustomResourceValidation(data []byte) {
	m1 := &apiextensionsv1.CustomResourceValidation{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.CustomResourceValidation{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1ExternalDocumentation(data []byte) {
	m1 := &apiextensionsv1.ExternalDocumentation{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.ExternalDocumentation{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1JSON(data []byte) {
	m1 := &apiextensionsv1.JSON{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.JSON{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1JSONSchemaProps(data []byte) {
	m1 := &apiextensionsv1.JSONSchemaProps{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.JSONSchemaProps{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1JSONSchemaPropsOrArray(data []byte) {
	m1 := &apiextensionsv1.JSONSchemaPropsOrArray{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.JSONSchemaPropsOrArray{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1JSONSchemaPropsOrBool(data []byte) {
	m1 := &apiextensionsv1.JSONSchemaPropsOrBool{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.JSONSchemaPropsOrBool{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1JSONSchemaPropsOrStringArray(data []byte) {
	m1 := &apiextensionsv1.JSONSchemaPropsOrStringArray{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.JSONSchemaPropsOrStringArray{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1ServiceReference(data []byte) {
	m1 := &apiextensionsv1.ServiceReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.ServiceReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1ValidationRule(data []byte) {
	m1 := &apiextensionsv1.ValidationRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.ValidationRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1WebhookClientConfig(data []byte) {
	m1 := &apiextensionsv1.WebhookClientConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.WebhookClientConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1WebhookConversion(data []byte) {
	m1 := &apiextensionsv1.WebhookConversion{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1.WebhookConversion{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1ConversionRequest(data []byte) {
	m1 := &apiextensionsv1beta1.ConversionRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.ConversionRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1ConversionResponse(data []byte) {
	m1 := &apiextensionsv1beta1.ConversionResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.ConversionResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1ConversionReview(data []byte) {
	m1 := &apiextensionsv1beta1.ConversionReview{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.ConversionReview{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceColumnDefinition(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceColumnDefinition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceColumnDefinition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceConversion(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceConversion{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceConversion{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceDefinition(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceDefinition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceDefinition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceDefinitionCondition(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceDefinitionCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceDefinitionCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceDefinitionList(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceDefinitionList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceDefinitionList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceDefinitionNames(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceDefinitionNames{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceDefinitionNames{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceDefinitionSpec(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceDefinitionSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceDefinitionSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceDefinitionStatus(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceDefinitionStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceDefinitionStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceDefinitionVersion(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceDefinitionVersion{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceDefinitionVersion{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceSubresourceScale(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceSubresourceScale{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceSubresourceScale{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceSubresourceStatus(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceSubresourceStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceSubresourceStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceSubresources(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceSubresources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceSubresources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1CustomResourceValidation(data []byte) {
	m1 := &apiextensionsv1beta1.CustomResourceValidation{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.CustomResourceValidation{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1ExternalDocumentation(data []byte) {
	m1 := &apiextensionsv1beta1.ExternalDocumentation{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.ExternalDocumentation{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1JSON(data []byte) {
	m1 := &apiextensionsv1beta1.JSON{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.JSON{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1JSONSchemaProps(data []byte) {
	m1 := &apiextensionsv1beta1.JSONSchemaProps{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.JSONSchemaProps{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1JSONSchemaPropsOrArray(data []byte) {
	m1 := &apiextensionsv1beta1.JSONSchemaPropsOrArray{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.JSONSchemaPropsOrArray{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1JSONSchemaPropsOrBool(data []byte) {
	m1 := &apiextensionsv1beta1.JSONSchemaPropsOrBool{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.JSONSchemaPropsOrBool{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1JSONSchemaPropsOrStringArray(data []byte) {
	m1 := &apiextensionsv1beta1.JSONSchemaPropsOrStringArray{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.JSONSchemaPropsOrStringArray{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1ServiceReference(data []byte) {
	m1 := &apiextensionsv1beta1.ServiceReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.ServiceReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1ValidationRule(data []byte) {
	m1 := &apiextensionsv1beta1.ValidationRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.ValidationRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiextensionsv1beta1WebhookClientConfig(data []byte) {
	m1 := &apiextensionsv1beta1.WebhookClientConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiextensionsv1beta1.WebhookClientConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1APIGroup(data []byte) {
	m1 := &metav1.APIGroup{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.APIGroup{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1APIGroupList(data []byte) {
	m1 := &metav1.APIGroupList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.APIGroupList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1APIResource(data []byte) {
	m1 := &metav1.APIResource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.APIResource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1APIResourceList(data []byte) {
	m1 := &metav1.APIResourceList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.APIResourceList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1APIVersions(data []byte) {
	m1 := &metav1.APIVersions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.APIVersions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1ApplyOptions(data []byte) {
	m1 := &metav1.ApplyOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.ApplyOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1Condition(data []byte) {
	m1 := &metav1.Condition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.Condition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1CreateOptions(data []byte) {
	m1 := &metav1.CreateOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.CreateOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1DeleteOptions(data []byte) {
	m1 := &metav1.DeleteOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.DeleteOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1Duration(data []byte) {
	m1 := &metav1.Duration{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.Duration{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1FieldsV1(data []byte) {
	m1 := &metav1.FieldsV1{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.FieldsV1{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1GetOptions(data []byte) {
	m1 := &metav1.GetOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.GetOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1GroupKind(data []byte) {
	m1 := &metav1.GroupKind{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.GroupKind{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1GroupResource(data []byte) {
	m1 := &metav1.GroupResource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.GroupResource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1GroupVersion(data []byte) {
	m1 := &metav1.GroupVersion{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.GroupVersion{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1GroupVersionForDiscovery(data []byte) {
	m1 := &metav1.GroupVersionForDiscovery{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.GroupVersionForDiscovery{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1GroupVersionKind(data []byte) {
	m1 := &metav1.GroupVersionKind{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.GroupVersionKind{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1GroupVersionResource(data []byte) {
	m1 := &metav1.GroupVersionResource{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.GroupVersionResource{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1LabelSelector(data []byte) {
	m1 := &metav1.LabelSelector{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.LabelSelector{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1LabelSelectorRequirement(data []byte) {
	m1 := &metav1.LabelSelectorRequirement{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.LabelSelectorRequirement{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1List(data []byte) {
	m1 := &metav1.List{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.List{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1ListMeta(data []byte) {
	m1 := &metav1.ListMeta{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.ListMeta{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1ListOptions(data []byte) {
	m1 := &metav1.ListOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.ListOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1ManagedFieldsEntry(data []byte) {
	m1 := &metav1.ManagedFieldsEntry{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.ManagedFieldsEntry{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1ObjectMeta(data []byte) {
	m1 := &metav1.ObjectMeta{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.ObjectMeta{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1OwnerReference(data []byte) {
	m1 := &metav1.OwnerReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.OwnerReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1PartialObjectMetadata(data []byte) {
	m1 := &metav1.PartialObjectMetadata{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.PartialObjectMetadata{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1PartialObjectMetadataList(data []byte) {
	m1 := &metav1.PartialObjectMetadataList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.PartialObjectMetadataList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1Patch(data []byte) {
	m1 := &metav1.Patch{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.Patch{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1PatchOptions(data []byte) {
	m1 := &metav1.PatchOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.PatchOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1Preconditions(data []byte) {
	m1 := &metav1.Preconditions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.Preconditions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1RootPaths(data []byte) {
	m1 := &metav1.RootPaths{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.RootPaths{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1ServerAddressByClientCIDR(data []byte) {
	m1 := &metav1.ServerAddressByClientCIDR{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.ServerAddressByClientCIDR{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1Status(data []byte) {
	m1 := &metav1.Status{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.Status{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1StatusCause(data []byte) {
	m1 := &metav1.StatusCause{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.StatusCause{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1StatusDetails(data []byte) {
	m1 := &metav1.StatusDetails{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.StatusDetails{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1TableOptions(data []byte) {
	m1 := &metav1.TableOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.TableOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1Timestamp(data []byte) {
	m1 := &metav1.Timestamp{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.Timestamp{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1TypeMeta(data []byte) {
	m1 := &metav1.TypeMeta{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.TypeMeta{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1UpdateOptions(data []byte) {
	m1 := &metav1.UpdateOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.UpdateOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1WatchEvent(data []byte) {
	m1 := &metav1.WatchEvent{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1.WatchEvent{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetav1beta1PartialObjectMetadataList(data []byte) {
	m1 := &metav1beta1.PartialObjectMetadataList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metav1beta1.PartialObjectMetadataList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzztestapigroupv1Carp(data []byte) {
	m1 := &testapigroupv1.Carp{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &testapigroupv1.Carp{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzztestapigroupv1CarpCondition(data []byte) {
	m1 := &testapigroupv1.CarpCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &testapigroupv1.CarpCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzztestapigroupv1CarpList(data []byte) {
	m1 := &testapigroupv1.CarpList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &testapigroupv1.CarpList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzztestapigroupv1CarpSpec(data []byte) {
	m1 := &testapigroupv1.CarpSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &testapigroupv1.CarpSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzztestapigroupv1CarpStatus(data []byte) {
	m1 := &testapigroupv1.CarpStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &testapigroupv1.CarpStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpkgruntimeRawExtension(data []byte) {
	m1 := &pkgruntime.RawExtension{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pkgruntime.RawExtension{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpkgruntimeTypeMeta(data []byte) {
	m1 := &pkgruntime.TypeMeta{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pkgruntime.TypeMeta{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpkgruntimeUnknown(data []byte) {
	m1 := &pkgruntime.Unknown{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pkgruntime.Unknown{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzutilintstrIntOrString(data []byte) {
	m1 := &utilintstr.IntOrString{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &utilintstr.IntOrString{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauditv1Event(data []byte) {
	m1 := &auditv1.Event{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &auditv1.Event{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauditv1EventList(data []byte) {
	m1 := &auditv1.EventList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &auditv1.EventList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauditv1GroupResources(data []byte) {
	m1 := &auditv1.GroupResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &auditv1.GroupResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauditv1ObjectReference(data []byte) {
	m1 := &auditv1.ObjectReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &auditv1.ObjectReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauditv1Policy(data []byte) {
	m1 := &auditv1.Policy{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &auditv1.Policy{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauditv1PolicyList(data []byte) {
	m1 := &auditv1.PolicyList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &auditv1.PolicyList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzauditv1PolicyRule(data []byte) {
	m1 := &auditv1.PolicyRule{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &auditv1.PolicyRule{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1VersionRequest(data []byte) {
	m1 := &runtimev1.VersionRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.VersionRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1VersionResponse(data []byte) {
	m1 := &runtimev1.VersionResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.VersionResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1DNSConfig(data []byte) {
	m1 := &runtimev1.DNSConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.DNSConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PortMapping(data []byte) {
	m1 := &runtimev1.PortMapping{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PortMapping{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1Mount(data []byte) {
	m1 := &runtimev1.Mount{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.Mount{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1NamespaceOption(data []byte) {
	m1 := &runtimev1.NamespaceOption{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.NamespaceOption{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1Int64Value(data []byte) {
	m1 := &runtimev1.Int64Value{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.Int64Value{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1LinuxSandboxSecurityContext(data []byte) {
	m1 := &runtimev1.LinuxSandboxSecurityContext{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.LinuxSandboxSecurityContext{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1SecurityProfile(data []byte) {
	m1 := &runtimev1.SecurityProfile{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.SecurityProfile{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1LinuxPodSandboxConfig(data []byte) {
	m1 := &runtimev1.LinuxPodSandboxConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.LinuxPodSandboxConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxMetadata(data []byte) {
	m1 := &runtimev1.PodSandboxMetadata{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxMetadata{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxConfig(data []byte) {
	m1 := &runtimev1.PodSandboxConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1RunPodSandboxRequest(data []byte) {
	m1 := &runtimev1.RunPodSandboxRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.RunPodSandboxRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1RunPodSandboxResponse(data []byte) {
	m1 := &runtimev1.RunPodSandboxResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.RunPodSandboxResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1StopPodSandboxRequest(data []byte) {
	m1 := &runtimev1.StopPodSandboxRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.StopPodSandboxRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1StopPodSandboxResponse(data []byte) {
	m1 := &runtimev1.StopPodSandboxResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.StopPodSandboxResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1RemovePodSandboxRequest(data []byte) {
	m1 := &runtimev1.RemovePodSandboxRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.RemovePodSandboxRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1RemovePodSandboxResponse(data []byte) {
	m1 := &runtimev1.RemovePodSandboxResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.RemovePodSandboxResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxStatusRequest(data []byte) {
	m1 := &runtimev1.PodSandboxStatusRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxStatusRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodIP(data []byte) {
	m1 := &runtimev1.PodIP{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodIP{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxNetworkStatus(data []byte) {
	m1 := &runtimev1.PodSandboxNetworkStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxNetworkStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1Namespace(data []byte) {
	m1 := &runtimev1.Namespace{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.Namespace{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1LinuxPodSandboxStatus(data []byte) {
	m1 := &runtimev1.LinuxPodSandboxStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.LinuxPodSandboxStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxStatus(data []byte) {
	m1 := &runtimev1.PodSandboxStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxStatusResponse(data []byte) {
	m1 := &runtimev1.PodSandboxStatusResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxStatusResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxStateValue(data []byte) {
	m1 := &runtimev1.PodSandboxStateValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxStateValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxFilter(data []byte) {
	m1 := &runtimev1.PodSandboxFilter{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxFilter{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ListPodSandboxRequest(data []byte) {
	m1 := &runtimev1.ListPodSandboxRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ListPodSandboxRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandbox(data []byte) {
	m1 := &runtimev1.PodSandbox{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandbox{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ListPodSandboxResponse(data []byte) {
	m1 := &runtimev1.ListPodSandboxResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ListPodSandboxResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxStatsRequest(data []byte) {
	m1 := &runtimev1.PodSandboxStatsRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxStatsRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxStatsResponse(data []byte) {
	m1 := &runtimev1.PodSandboxStatsResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxStatsResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxStatsFilter(data []byte) {
	m1 := &runtimev1.PodSandboxStatsFilter{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxStatsFilter{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ListPodSandboxStatsRequest(data []byte) {
	m1 := &runtimev1.ListPodSandboxStatsRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ListPodSandboxStatsRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ListPodSandboxStatsResponse(data []byte) {
	m1 := &runtimev1.ListPodSandboxStatsResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ListPodSandboxStatsResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxAttributes(data []byte) {
	m1 := &runtimev1.PodSandboxAttributes{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxAttributes{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PodSandboxStats(data []byte) {
	m1 := &runtimev1.PodSandboxStats{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PodSandboxStats{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1LinuxPodSandboxStats(data []byte) {
	m1 := &runtimev1.LinuxPodSandboxStats{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.LinuxPodSandboxStats{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1WindowsPodSandboxStats(data []byte) {
	m1 := &runtimev1.WindowsPodSandboxStats{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.WindowsPodSandboxStats{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1NetworkUsage(data []byte) {
	m1 := &runtimev1.NetworkUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.NetworkUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1NetworkInterfaceUsage(data []byte) {
	m1 := &runtimev1.NetworkInterfaceUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.NetworkInterfaceUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ProcessUsage(data []byte) {
	m1 := &runtimev1.ProcessUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ProcessUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ImageSpec(data []byte) {
	m1 := &runtimev1.ImageSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ImageSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1KeyValue(data []byte) {
	m1 := &runtimev1.KeyValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.KeyValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1LinuxContainerResources(data []byte) {
	m1 := &runtimev1.LinuxContainerResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.LinuxContainerResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1HugepageLimit(data []byte) {
	m1 := &runtimev1.HugepageLimit{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.HugepageLimit{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1SELinuxOption(data []byte) {
	m1 := &runtimev1.SELinuxOption{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.SELinuxOption{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1Capability(data []byte) {
	m1 := &runtimev1.Capability{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.Capability{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1LinuxContainerSecurityContext(data []byte) {
	m1 := &runtimev1.LinuxContainerSecurityContext{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.LinuxContainerSecurityContext{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1LinuxContainerConfig(data []byte) {
	m1 := &runtimev1.LinuxContainerConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.LinuxContainerConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1WindowsSandboxSecurityContext(data []byte) {
	m1 := &runtimev1.WindowsSandboxSecurityContext{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.WindowsSandboxSecurityContext{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1WindowsPodSandboxConfig(data []byte) {
	m1 := &runtimev1.WindowsPodSandboxConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.WindowsPodSandboxConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1WindowsContainerSecurityContext(data []byte) {
	m1 := &runtimev1.WindowsContainerSecurityContext{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.WindowsContainerSecurityContext{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1WindowsContainerConfig(data []byte) {
	m1 := &runtimev1.WindowsContainerConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.WindowsContainerConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1WindowsContainerResources(data []byte) {
	m1 := &runtimev1.WindowsContainerResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.WindowsContainerResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerMetadata(data []byte) {
	m1 := &runtimev1.ContainerMetadata{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerMetadata{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1Device(data []byte) {
	m1 := &runtimev1.Device{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.Device{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerConfig(data []byte) {
	m1 := &runtimev1.ContainerConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1CreateContainerRequest(data []byte) {
	m1 := &runtimev1.CreateContainerRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.CreateContainerRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1CreateContainerResponse(data []byte) {
	m1 := &runtimev1.CreateContainerResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.CreateContainerResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1StartContainerRequest(data []byte) {
	m1 := &runtimev1.StartContainerRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.StartContainerRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1StartContainerResponse(data []byte) {
	m1 := &runtimev1.StartContainerResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.StartContainerResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1StopContainerRequest(data []byte) {
	m1 := &runtimev1.StopContainerRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.StopContainerRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1StopContainerResponse(data []byte) {
	m1 := &runtimev1.StopContainerResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.StopContainerResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1RemoveContainerRequest(data []byte) {
	m1 := &runtimev1.RemoveContainerRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.RemoveContainerRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1RemoveContainerResponse(data []byte) {
	m1 := &runtimev1.RemoveContainerResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.RemoveContainerResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerStateValue(data []byte) {
	m1 := &runtimev1.ContainerStateValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerStateValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerFilter(data []byte) {
	m1 := &runtimev1.ContainerFilter{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerFilter{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ListContainersRequest(data []byte) {
	m1 := &runtimev1.ListContainersRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ListContainersRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1Container(data []byte) {
	m1 := &runtimev1.Container{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.Container{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ListContainersResponse(data []byte) {
	m1 := &runtimev1.ListContainersResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ListContainersResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerStatusRequest(data []byte) {
	m1 := &runtimev1.ContainerStatusRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerStatusRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerStatus(data []byte) {
	m1 := &runtimev1.ContainerStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerStatusResponse(data []byte) {
	m1 := &runtimev1.ContainerStatusResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerStatusResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1UpdateContainerResourcesRequest(data []byte) {
	m1 := &runtimev1.UpdateContainerResourcesRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.UpdateContainerResourcesRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1UpdateContainerResourcesResponse(data []byte) {
	m1 := &runtimev1.UpdateContainerResourcesResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.UpdateContainerResourcesResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ExecSyncRequest(data []byte) {
	m1 := &runtimev1.ExecSyncRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ExecSyncRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ExecSyncResponse(data []byte) {
	m1 := &runtimev1.ExecSyncResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ExecSyncResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ExecRequest(data []byte) {
	m1 := &runtimev1.ExecRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ExecRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ExecResponse(data []byte) {
	m1 := &runtimev1.ExecResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ExecResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1AttachRequest(data []byte) {
	m1 := &runtimev1.AttachRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.AttachRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1AttachResponse(data []byte) {
	m1 := &runtimev1.AttachResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.AttachResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PortForwardRequest(data []byte) {
	m1 := &runtimev1.PortForwardRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PortForwardRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PortForwardResponse(data []byte) {
	m1 := &runtimev1.PortForwardResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PortForwardResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ImageFilter(data []byte) {
	m1 := &runtimev1.ImageFilter{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ImageFilter{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ListImagesRequest(data []byte) {
	m1 := &runtimev1.ListImagesRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ListImagesRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1Image(data []byte) {
	m1 := &runtimev1.Image{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.Image{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ListImagesResponse(data []byte) {
	m1 := &runtimev1.ListImagesResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ListImagesResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ImageStatusRequest(data []byte) {
	m1 := &runtimev1.ImageStatusRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ImageStatusRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ImageStatusResponse(data []byte) {
	m1 := &runtimev1.ImageStatusResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ImageStatusResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1AuthConfig(data []byte) {
	m1 := &runtimev1.AuthConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.AuthConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PullImageRequest(data []byte) {
	m1 := &runtimev1.PullImageRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PullImageRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1PullImageResponse(data []byte) {
	m1 := &runtimev1.PullImageResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.PullImageResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1RemoveImageRequest(data []byte) {
	m1 := &runtimev1.RemoveImageRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.RemoveImageRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1RemoveImageResponse(data []byte) {
	m1 := &runtimev1.RemoveImageResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.RemoveImageResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1NetworkConfig(data []byte) {
	m1 := &runtimev1.NetworkConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.NetworkConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1RuntimeConfig(data []byte) {
	m1 := &runtimev1.RuntimeConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.RuntimeConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1UpdateRuntimeConfigRequest(data []byte) {
	m1 := &runtimev1.UpdateRuntimeConfigRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.UpdateRuntimeConfigRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1UpdateRuntimeConfigResponse(data []byte) {
	m1 := &runtimev1.UpdateRuntimeConfigResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.UpdateRuntimeConfigResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1RuntimeCondition(data []byte) {
	m1 := &runtimev1.RuntimeCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.RuntimeCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1RuntimeStatus(data []byte) {
	m1 := &runtimev1.RuntimeStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.RuntimeStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1StatusRequest(data []byte) {
	m1 := &runtimev1.StatusRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.StatusRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1StatusResponse(data []byte) {
	m1 := &runtimev1.StatusResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.StatusResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ImageFsInfoRequest(data []byte) {
	m1 := &runtimev1.ImageFsInfoRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ImageFsInfoRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1UInt64Value(data []byte) {
	m1 := &runtimev1.UInt64Value{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.UInt64Value{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1FilesystemIdentifier(data []byte) {
	m1 := &runtimev1.FilesystemIdentifier{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.FilesystemIdentifier{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1FilesystemUsage(data []byte) {
	m1 := &runtimev1.FilesystemUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.FilesystemUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ImageFsInfoResponse(data []byte) {
	m1 := &runtimev1.ImageFsInfoResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ImageFsInfoResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerStatsRequest(data []byte) {
	m1 := &runtimev1.ContainerStatsRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerStatsRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerStatsResponse(data []byte) {
	m1 := &runtimev1.ContainerStatsResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerStatsResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ListContainerStatsRequest(data []byte) {
	m1 := &runtimev1.ListContainerStatsRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ListContainerStatsRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerStatsFilter(data []byte) {
	m1 := &runtimev1.ContainerStatsFilter{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerStatsFilter{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ListContainerStatsResponse(data []byte) {
	m1 := &runtimev1.ListContainerStatsResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ListContainerStatsResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerAttributes(data []byte) {
	m1 := &runtimev1.ContainerAttributes{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerAttributes{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ContainerStats(data []byte) {
	m1 := &runtimev1.ContainerStats{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ContainerStats{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1CpuUsage(data []byte) {
	m1 := &runtimev1.CpuUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.CpuUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1MemoryUsage(data []byte) {
	m1 := &runtimev1.MemoryUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.MemoryUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ReopenContainerLogRequest(data []byte) {
	m1 := &runtimev1.ReopenContainerLogRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ReopenContainerLogRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1ReopenContainerLogResponse(data []byte) {
	m1 := &runtimev1.ReopenContainerLogResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1.ReopenContainerLogResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2VersionRequest(data []byte) {
	m1 := &runtimev1alpha2.VersionRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.VersionRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2VersionResponse(data []byte) {
	m1 := &runtimev1alpha2.VersionResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.VersionResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2DNSConfig(data []byte) {
	m1 := &runtimev1alpha2.DNSConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.DNSConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PortMapping(data []byte) {
	m1 := &runtimev1alpha2.PortMapping{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PortMapping{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2Mount(data []byte) {
	m1 := &runtimev1alpha2.Mount{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.Mount{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2NamespaceOption(data []byte) {
	m1 := &runtimev1alpha2.NamespaceOption{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.NamespaceOption{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2Int64Value(data []byte) {
	m1 := &runtimev1alpha2.Int64Value{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.Int64Value{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2LinuxSandboxSecurityContext(data []byte) {
	m1 := &runtimev1alpha2.LinuxSandboxSecurityContext{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.LinuxSandboxSecurityContext{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2SecurityProfile(data []byte) {
	m1 := &runtimev1alpha2.SecurityProfile{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.SecurityProfile{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2LinuxPodSandboxConfig(data []byte) {
	m1 := &runtimev1alpha2.LinuxPodSandboxConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.LinuxPodSandboxConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxMetadata(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxMetadata{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxMetadata{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxConfig(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2RunPodSandboxRequest(data []byte) {
	m1 := &runtimev1alpha2.RunPodSandboxRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.RunPodSandboxRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2RunPodSandboxResponse(data []byte) {
	m1 := &runtimev1alpha2.RunPodSandboxResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.RunPodSandboxResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2StopPodSandboxRequest(data []byte) {
	m1 := &runtimev1alpha2.StopPodSandboxRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.StopPodSandboxRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2StopPodSandboxResponse(data []byte) {
	m1 := &runtimev1alpha2.StopPodSandboxResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.StopPodSandboxResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2RemovePodSandboxRequest(data []byte) {
	m1 := &runtimev1alpha2.RemovePodSandboxRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.RemovePodSandboxRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2RemovePodSandboxResponse(data []byte) {
	m1 := &runtimev1alpha2.RemovePodSandboxResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.RemovePodSandboxResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxStatusRequest(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxStatusRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxStatusRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodIP(data []byte) {
	m1 := &runtimev1alpha2.PodIP{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodIP{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxNetworkStatus(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxNetworkStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxNetworkStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2Namespace(data []byte) {
	m1 := &runtimev1alpha2.Namespace{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.Namespace{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2LinuxPodSandboxStatus(data []byte) {
	m1 := &runtimev1alpha2.LinuxPodSandboxStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.LinuxPodSandboxStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxStatus(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxStatusResponse(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxStatusResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxStatusResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxStateValue(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxStateValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxStateValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxFilter(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxFilter{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxFilter{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ListPodSandboxRequest(data []byte) {
	m1 := &runtimev1alpha2.ListPodSandboxRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ListPodSandboxRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandbox(data []byte) {
	m1 := &runtimev1alpha2.PodSandbox{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandbox{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ListPodSandboxResponse(data []byte) {
	m1 := &runtimev1alpha2.ListPodSandboxResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ListPodSandboxResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxStatsRequest(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxStatsRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxStatsRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxStatsResponse(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxStatsResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxStatsResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxStatsFilter(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxStatsFilter{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxStatsFilter{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ListPodSandboxStatsRequest(data []byte) {
	m1 := &runtimev1alpha2.ListPodSandboxStatsRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ListPodSandboxStatsRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ListPodSandboxStatsResponse(data []byte) {
	m1 := &runtimev1alpha2.ListPodSandboxStatsResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ListPodSandboxStatsResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxAttributes(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxAttributes{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxAttributes{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PodSandboxStats(data []byte) {
	m1 := &runtimev1alpha2.PodSandboxStats{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PodSandboxStats{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2LinuxPodSandboxStats(data []byte) {
	m1 := &runtimev1alpha2.LinuxPodSandboxStats{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.LinuxPodSandboxStats{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2WindowsPodSandboxStats(data []byte) {
	m1 := &runtimev1alpha2.WindowsPodSandboxStats{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.WindowsPodSandboxStats{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2NetworkUsage(data []byte) {
	m1 := &runtimev1alpha2.NetworkUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.NetworkUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2NetworkInterfaceUsage(data []byte) {
	m1 := &runtimev1alpha2.NetworkInterfaceUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.NetworkInterfaceUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ProcessUsage(data []byte) {
	m1 := &runtimev1alpha2.ProcessUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ProcessUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ImageSpec(data []byte) {
	m1 := &runtimev1alpha2.ImageSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ImageSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2KeyValue(data []byte) {
	m1 := &runtimev1alpha2.KeyValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.KeyValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2LinuxContainerResources(data []byte) {
	m1 := &runtimev1alpha2.LinuxContainerResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.LinuxContainerResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2HugepageLimit(data []byte) {
	m1 := &runtimev1alpha2.HugepageLimit{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.HugepageLimit{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2SELinuxOption(data []byte) {
	m1 := &runtimev1alpha2.SELinuxOption{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.SELinuxOption{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2Capability(data []byte) {
	m1 := &runtimev1alpha2.Capability{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.Capability{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2LinuxContainerSecurityContext(data []byte) {
	m1 := &runtimev1alpha2.LinuxContainerSecurityContext{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.LinuxContainerSecurityContext{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2LinuxContainerConfig(data []byte) {
	m1 := &runtimev1alpha2.LinuxContainerConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.LinuxContainerConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2WindowsSandboxSecurityContext(data []byte) {
	m1 := &runtimev1alpha2.WindowsSandboxSecurityContext{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.WindowsSandboxSecurityContext{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2WindowsPodSandboxConfig(data []byte) {
	m1 := &runtimev1alpha2.WindowsPodSandboxConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.WindowsPodSandboxConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2WindowsContainerSecurityContext(data []byte) {
	m1 := &runtimev1alpha2.WindowsContainerSecurityContext{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.WindowsContainerSecurityContext{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2WindowsContainerConfig(data []byte) {
	m1 := &runtimev1alpha2.WindowsContainerConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.WindowsContainerConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2WindowsContainerResources(data []byte) {
	m1 := &runtimev1alpha2.WindowsContainerResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.WindowsContainerResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerMetadata(data []byte) {
	m1 := &runtimev1alpha2.ContainerMetadata{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerMetadata{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2Device(data []byte) {
	m1 := &runtimev1alpha2.Device{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.Device{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerConfig(data []byte) {
	m1 := &runtimev1alpha2.ContainerConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2CreateContainerRequest(data []byte) {
	m1 := &runtimev1alpha2.CreateContainerRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.CreateContainerRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2CreateContainerResponse(data []byte) {
	m1 := &runtimev1alpha2.CreateContainerResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.CreateContainerResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2StartContainerRequest(data []byte) {
	m1 := &runtimev1alpha2.StartContainerRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.StartContainerRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2StartContainerResponse(data []byte) {
	m1 := &runtimev1alpha2.StartContainerResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.StartContainerResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2StopContainerRequest(data []byte) {
	m1 := &runtimev1alpha2.StopContainerRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.StopContainerRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2StopContainerResponse(data []byte) {
	m1 := &runtimev1alpha2.StopContainerResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.StopContainerResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2RemoveContainerRequest(data []byte) {
	m1 := &runtimev1alpha2.RemoveContainerRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.RemoveContainerRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2RemoveContainerResponse(data []byte) {
	m1 := &runtimev1alpha2.RemoveContainerResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.RemoveContainerResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerStateValue(data []byte) {
	m1 := &runtimev1alpha2.ContainerStateValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerStateValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerFilter(data []byte) {
	m1 := &runtimev1alpha2.ContainerFilter{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerFilter{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ListContainersRequest(data []byte) {
	m1 := &runtimev1alpha2.ListContainersRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ListContainersRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2Container(data []byte) {
	m1 := &runtimev1alpha2.Container{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.Container{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ListContainersResponse(data []byte) {
	m1 := &runtimev1alpha2.ListContainersResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ListContainersResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerStatusRequest(data []byte) {
	m1 := &runtimev1alpha2.ContainerStatusRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerStatusRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerStatus(data []byte) {
	m1 := &runtimev1alpha2.ContainerStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerStatusResponse(data []byte) {
	m1 := &runtimev1alpha2.ContainerStatusResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerStatusResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2UpdateContainerResourcesRequest(data []byte) {
	m1 := &runtimev1alpha2.UpdateContainerResourcesRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.UpdateContainerResourcesRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2UpdateContainerResourcesResponse(data []byte) {
	m1 := &runtimev1alpha2.UpdateContainerResourcesResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.UpdateContainerResourcesResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ExecSyncRequest(data []byte) {
	m1 := &runtimev1alpha2.ExecSyncRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ExecSyncRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ExecSyncResponse(data []byte) {
	m1 := &runtimev1alpha2.ExecSyncResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ExecSyncResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ExecRequest(data []byte) {
	m1 := &runtimev1alpha2.ExecRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ExecRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ExecResponse(data []byte) {
	m1 := &runtimev1alpha2.ExecResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ExecResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2AttachRequest(data []byte) {
	m1 := &runtimev1alpha2.AttachRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.AttachRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2AttachResponse(data []byte) {
	m1 := &runtimev1alpha2.AttachResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.AttachResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PortForwardRequest(data []byte) {
	m1 := &runtimev1alpha2.PortForwardRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PortForwardRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PortForwardResponse(data []byte) {
	m1 := &runtimev1alpha2.PortForwardResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PortForwardResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ImageFilter(data []byte) {
	m1 := &runtimev1alpha2.ImageFilter{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ImageFilter{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ListImagesRequest(data []byte) {
	m1 := &runtimev1alpha2.ListImagesRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ListImagesRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2Image(data []byte) {
	m1 := &runtimev1alpha2.Image{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.Image{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ListImagesResponse(data []byte) {
	m1 := &runtimev1alpha2.ListImagesResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ListImagesResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ImageStatusRequest(data []byte) {
	m1 := &runtimev1alpha2.ImageStatusRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ImageStatusRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ImageStatusResponse(data []byte) {
	m1 := &runtimev1alpha2.ImageStatusResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ImageStatusResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2AuthConfig(data []byte) {
	m1 := &runtimev1alpha2.AuthConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.AuthConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PullImageRequest(data []byte) {
	m1 := &runtimev1alpha2.PullImageRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PullImageRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2PullImageResponse(data []byte) {
	m1 := &runtimev1alpha2.PullImageResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.PullImageResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2RemoveImageRequest(data []byte) {
	m1 := &runtimev1alpha2.RemoveImageRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.RemoveImageRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2RemoveImageResponse(data []byte) {
	m1 := &runtimev1alpha2.RemoveImageResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.RemoveImageResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2NetworkConfig(data []byte) {
	m1 := &runtimev1alpha2.NetworkConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.NetworkConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2RuntimeConfig(data []byte) {
	m1 := &runtimev1alpha2.RuntimeConfig{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.RuntimeConfig{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2UpdateRuntimeConfigRequest(data []byte) {
	m1 := &runtimev1alpha2.UpdateRuntimeConfigRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.UpdateRuntimeConfigRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2UpdateRuntimeConfigResponse(data []byte) {
	m1 := &runtimev1alpha2.UpdateRuntimeConfigResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.UpdateRuntimeConfigResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2RuntimeCondition(data []byte) {
	m1 := &runtimev1alpha2.RuntimeCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.RuntimeCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2RuntimeStatus(data []byte) {
	m1 := &runtimev1alpha2.RuntimeStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.RuntimeStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2StatusRequest(data []byte) {
	m1 := &runtimev1alpha2.StatusRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.StatusRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2StatusResponse(data []byte) {
	m1 := &runtimev1alpha2.StatusResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.StatusResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ImageFsInfoRequest(data []byte) {
	m1 := &runtimev1alpha2.ImageFsInfoRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ImageFsInfoRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2UInt64Value(data []byte) {
	m1 := &runtimev1alpha2.UInt64Value{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.UInt64Value{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2FilesystemIdentifier(data []byte) {
	m1 := &runtimev1alpha2.FilesystemIdentifier{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.FilesystemIdentifier{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2FilesystemUsage(data []byte) {
	m1 := &runtimev1alpha2.FilesystemUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.FilesystemUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ImageFsInfoResponse(data []byte) {
	m1 := &runtimev1alpha2.ImageFsInfoResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ImageFsInfoResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerStatsRequest(data []byte) {
	m1 := &runtimev1alpha2.ContainerStatsRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerStatsRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerStatsResponse(data []byte) {
	m1 := &runtimev1alpha2.ContainerStatsResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerStatsResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ListContainerStatsRequest(data []byte) {
	m1 := &runtimev1alpha2.ListContainerStatsRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ListContainerStatsRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerStatsFilter(data []byte) {
	m1 := &runtimev1alpha2.ContainerStatsFilter{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerStatsFilter{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ListContainerStatsResponse(data []byte) {
	m1 := &runtimev1alpha2.ListContainerStatsResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ListContainerStatsResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerAttributes(data []byte) {
	m1 := &runtimev1alpha2.ContainerAttributes{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerAttributes{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ContainerStats(data []byte) {
	m1 := &runtimev1alpha2.ContainerStats{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ContainerStats{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2CpuUsage(data []byte) {
	m1 := &runtimev1alpha2.CpuUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.CpuUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2MemoryUsage(data []byte) {
	m1 := &runtimev1alpha2.MemoryUsage{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.MemoryUsage{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ReopenContainerLogRequest(data []byte) {
	m1 := &runtimev1alpha2.ReopenContainerLogRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ReopenContainerLogRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzruntimev1alpha2ReopenContainerLogResponse(data []byte) {
	m1 := &runtimev1alpha2.ReopenContainerLogResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &runtimev1alpha2.ReopenContainerLogResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1APIService(data []byte) {
	m1 := &apiregistrationv1.APIService{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1.APIService{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1APIServiceCondition(data []byte) {
	m1 := &apiregistrationv1.APIServiceCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1.APIServiceCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1APIServiceList(data []byte) {
	m1 := &apiregistrationv1.APIServiceList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1.APIServiceList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1APIServiceSpec(data []byte) {
	m1 := &apiregistrationv1.APIServiceSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1.APIServiceSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1APIServiceStatus(data []byte) {
	m1 := &apiregistrationv1.APIServiceStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1.APIServiceStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1ServiceReference(data []byte) {
	m1 := &apiregistrationv1.ServiceReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1.ServiceReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1beta1APIService(data []byte) {
	m1 := &apiregistrationv1beta1.APIService{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1beta1.APIService{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1beta1APIServiceCondition(data []byte) {
	m1 := &apiregistrationv1beta1.APIServiceCondition{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1beta1.APIServiceCondition{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1beta1APIServiceList(data []byte) {
	m1 := &apiregistrationv1beta1.APIServiceList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1beta1.APIServiceList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1beta1APIServiceSpec(data []byte) {
	m1 := &apiregistrationv1beta1.APIServiceSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1beta1.APIServiceSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1beta1APIServiceStatus(data []byte) {
	m1 := &apiregistrationv1beta1.APIServiceStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1beta1.APIServiceStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzapiregistrationv1beta1ServiceReference(data []byte) {
	m1 := &apiregistrationv1beta1.ServiceReference{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &apiregistrationv1beta1.ServiceReference{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1alphaRegisterRequest(data []byte) {
	m1 := &devicepluginv1alpha.RegisterRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1alpha.RegisterRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1alphaEmpty(data []byte) {
	m1 := &devicepluginv1alpha.Empty{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1alpha.Empty{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1alphaListAndWatchResponse(data []byte) {
	m1 := &devicepluginv1alpha.ListAndWatchResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1alpha.ListAndWatchResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1alphaDevice(data []byte) {
	m1 := &devicepluginv1alpha.Device{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1alpha.Device{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1alphaAllocateRequest(data []byte) {
	m1 := &devicepluginv1alpha.AllocateRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1alpha.AllocateRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1alphaAllocateResponse(data []byte) {
	m1 := &devicepluginv1alpha.AllocateResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1alpha.AllocateResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1alphaMount(data []byte) {
	m1 := &devicepluginv1alpha.Mount{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1alpha.Mount{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1alphaDeviceSpec(data []byte) {
	m1 := &devicepluginv1alpha.DeviceSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1alpha.DeviceSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1DevicePluginOptions(data []byte) {
	m1 := &devicepluginv1beta1.DevicePluginOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.DevicePluginOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1RegisterRequest(data []byte) {
	m1 := &devicepluginv1beta1.RegisterRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.RegisterRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1Empty(data []byte) {
	m1 := &devicepluginv1beta1.Empty{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.Empty{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1ListAndWatchResponse(data []byte) {
	m1 := &devicepluginv1beta1.ListAndWatchResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.ListAndWatchResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1TopologyInfo(data []byte) {
	m1 := &devicepluginv1beta1.TopologyInfo{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.TopologyInfo{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1NUMANode(data []byte) {
	m1 := &devicepluginv1beta1.NUMANode{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.NUMANode{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1Device(data []byte) {
	m1 := &devicepluginv1beta1.Device{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.Device{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1PreStartContainerRequest(data []byte) {
	m1 := &devicepluginv1beta1.PreStartContainerRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.PreStartContainerRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1PreStartContainerResponse(data []byte) {
	m1 := &devicepluginv1beta1.PreStartContainerResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.PreStartContainerResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1PreferredAllocationRequest(data []byte) {
	m1 := &devicepluginv1beta1.PreferredAllocationRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.PreferredAllocationRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1ContainerPreferredAllocationRequest(data []byte) {
	m1 := &devicepluginv1beta1.ContainerPreferredAllocationRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.ContainerPreferredAllocationRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1PreferredAllocationResponse(data []byte) {
	m1 := &devicepluginv1beta1.PreferredAllocationResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.PreferredAllocationResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1ContainerPreferredAllocationResponse(data []byte) {
	m1 := &devicepluginv1beta1.ContainerPreferredAllocationResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.ContainerPreferredAllocationResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1AllocateRequest(data []byte) {
	m1 := &devicepluginv1beta1.AllocateRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.AllocateRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1ContainerAllocateRequest(data []byte) {
	m1 := &devicepluginv1beta1.ContainerAllocateRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.ContainerAllocateRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1AllocateResponse(data []byte) {
	m1 := &devicepluginv1beta1.AllocateResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.AllocateResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1ContainerAllocateResponse(data []byte) {
	m1 := &devicepluginv1beta1.ContainerAllocateResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.ContainerAllocateResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1Mount(data []byte) {
	m1 := &devicepluginv1beta1.Mount{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.Mount{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzdevicepluginv1beta1DeviceSpec(data []byte) {
	m1 := &devicepluginv1beta1.DeviceSpec{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &devicepluginv1beta1.DeviceSpec{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1PluginInfo(data []byte) {
	m1 := &pluginregistrationv1.PluginInfo{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1.PluginInfo{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1RegistrationStatus(data []byte) {
	m1 := &pluginregistrationv1.RegistrationStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1.RegistrationStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1RegistrationStatusResponse(data []byte) {
	m1 := &pluginregistrationv1.RegistrationStatusResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1.RegistrationStatusResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1InfoRequest(data []byte) {
	m1 := &pluginregistrationv1.InfoRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1.InfoRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1alpha1PluginInfo(data []byte) {
	m1 := &pluginregistrationv1alpha1.PluginInfo{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1alpha1.PluginInfo{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1alpha1RegistrationStatus(data []byte) {
	m1 := &pluginregistrationv1alpha1.RegistrationStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1alpha1.RegistrationStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1alpha1RegistrationStatusResponse(data []byte) {
	m1 := &pluginregistrationv1alpha1.RegistrationStatusResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1alpha1.RegistrationStatusResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1alpha1InfoRequest(data []byte) {
	m1 := &pluginregistrationv1alpha1.InfoRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1alpha1.InfoRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1beta1PluginInfo(data []byte) {
	m1 := &pluginregistrationv1beta1.PluginInfo{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1beta1.PluginInfo{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1beta1RegistrationStatus(data []byte) {
	m1 := &pluginregistrationv1beta1.RegistrationStatus{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1beta1.RegistrationStatus{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1beta1RegistrationStatusResponse(data []byte) {
	m1 := &pluginregistrationv1beta1.RegistrationStatusResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1beta1.RegistrationStatusResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpluginregistrationv1beta1InfoRequest(data []byte) {
	m1 := &pluginregistrationv1beta1.InfoRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &pluginregistrationv1beta1.InfoRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1AllocatableResourcesRequest(data []byte) {
	m1 := &podresourcesv1.AllocatableResourcesRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1.AllocatableResourcesRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1AllocatableResourcesResponse(data []byte) {
	m1 := &podresourcesv1.AllocatableResourcesResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1.AllocatableResourcesResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1ListPodResourcesRequest(data []byte) {
	m1 := &podresourcesv1.ListPodResourcesRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1.ListPodResourcesRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1ListPodResourcesResponse(data []byte) {
	m1 := &podresourcesv1.ListPodResourcesResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1.ListPodResourcesResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1PodResources(data []byte) {
	m1 := &podresourcesv1.PodResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1.PodResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1ContainerResources(data []byte) {
	m1 := &podresourcesv1.ContainerResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1.ContainerResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1ContainerMemory(data []byte) {
	m1 := &podresourcesv1.ContainerMemory{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1.ContainerMemory{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1ContainerDevices(data []byte) {
	m1 := &podresourcesv1.ContainerDevices{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1.ContainerDevices{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1TopologyInfo(data []byte) {
	m1 := &podresourcesv1.TopologyInfo{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1.TopologyInfo{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1NUMANode(data []byte) {
	m1 := &podresourcesv1.NUMANode{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1.NUMANode{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1alpha1ListPodResourcesRequest(data []byte) {
	m1 := &podresourcesv1alpha1.ListPodResourcesRequest{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1alpha1.ListPodResourcesRequest{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1alpha1ListPodResourcesResponse(data []byte) {
	m1 := &podresourcesv1alpha1.ListPodResourcesResponse{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1alpha1.ListPodResourcesResponse{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1alpha1PodResources(data []byte) {
	m1 := &podresourcesv1alpha1.PodResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1alpha1.PodResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1alpha1ContainerResources(data []byte) {
	m1 := &podresourcesv1alpha1.ContainerResources{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1alpha1.ContainerResources{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzpodresourcesv1alpha1ContainerDevices(data []byte) {
	m1 := &podresourcesv1alpha1.ContainerDevices{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &podresourcesv1alpha1.ContainerDevices{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcustom_metricsv1beta1MetricListOptions(data []byte) {
	m1 := &custom_metricsv1beta1.MetricListOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &custom_metricsv1beta1.MetricListOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcustom_metricsv1beta1MetricValue(data []byte) {
	m1 := &custom_metricsv1beta1.MetricValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &custom_metricsv1beta1.MetricValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcustom_metricsv1beta1MetricValueList(data []byte) {
	m1 := &custom_metricsv1beta1.MetricValueList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &custom_metricsv1beta1.MetricValueList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcustom_metricsv1beta2MetricIdentifier(data []byte) {
	m1 := &custom_metricsv1beta2.MetricIdentifier{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &custom_metricsv1beta2.MetricIdentifier{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcustom_metricsv1beta2MetricListOptions(data []byte) {
	m1 := &custom_metricsv1beta2.MetricListOptions{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &custom_metricsv1beta2.MetricListOptions{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcustom_metricsv1beta2MetricValue(data []byte) {
	m1 := &custom_metricsv1beta2.MetricValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &custom_metricsv1beta2.MetricValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzcustom_metricsv1beta2MetricValueList(data []byte) {
	m1 := &custom_metricsv1beta2.MetricValueList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &custom_metricsv1beta2.MetricValueList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzexternal_metricsv1beta1ExternalMetricValue(data []byte) {
	m1 := &external_metricsv1beta1.ExternalMetricValue{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &external_metricsv1beta1.ExternalMetricValue{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzexternal_metricsv1beta1ExternalMetricValueList(data []byte) {
	m1 := &external_metricsv1beta1.ExternalMetricValueList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &external_metricsv1beta1.ExternalMetricValueList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetricsv1alpha1ContainerMetrics(data []byte) {
	m1 := &metricsv1alpha1.ContainerMetrics{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metricsv1alpha1.ContainerMetrics{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetricsv1alpha1NodeMetrics(data []byte) {
	m1 := &metricsv1alpha1.NodeMetrics{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metricsv1alpha1.NodeMetrics{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetricsv1alpha1NodeMetricsList(data []byte) {
	m1 := &metricsv1alpha1.NodeMetricsList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metricsv1alpha1.NodeMetricsList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetricsv1alpha1PodMetrics(data []byte) {
	m1 := &metricsv1alpha1.PodMetrics{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metricsv1alpha1.PodMetrics{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetricsv1alpha1PodMetricsList(data []byte) {
	m1 := &metricsv1alpha1.PodMetricsList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metricsv1alpha1.PodMetricsList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetricsv1beta1ContainerMetrics(data []byte) {
	m1 := &metricsv1beta1.ContainerMetrics{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metricsv1beta1.ContainerMetrics{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetricsv1beta1NodeMetrics(data []byte) {
	m1 := &metricsv1beta1.NodeMetrics{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metricsv1beta1.NodeMetrics{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetricsv1beta1NodeMetricsList(data []byte) {
	m1 := &metricsv1beta1.NodeMetricsList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metricsv1beta1.NodeMetricsList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetricsv1beta1PodMetrics(data []byte) {
	m1 := &metricsv1beta1.PodMetrics{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metricsv1beta1.PodMetrics{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}


func fuzzmetricsv1beta1PodMetricsList(data []byte) {
	m1 := &metricsv1beta1.PodMetricsList{}
	data2 := data
	err := m1.Unmarshal(data)
	if err != nil {
		return
	}
	correctData1, err := m1.Marshal()
	if err != nil {
		panic(err)
	}
	m2 := &metricsv1beta1.PodMetricsList{}
	err = m2.Unmarshal(data2)
	if err != nil {
		panic(err)
	}
	correctData2, err := m2.Marshal()
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(m1, m2) {
		fmt.Printf("%+v\n", m1)
		fmt.Printf("%+v\n", m2)
		panic("done")
	}
	checkData(correctData1, correctData2)
}

