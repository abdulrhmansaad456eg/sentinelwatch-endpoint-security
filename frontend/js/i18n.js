const translations = {
    en: {
        nav_dashboard: "Dashboard",
        nav_processes: "Processes",
        nav_network: "Network",
        nav_events: "Security Events",
        nav_alerts: "Alerts",
        section_tools: "Tools",
        nav_baseline: "Baseline Training",
        nav_simulation: "Threat Simulation",
        refresh: "Refresh",
        export: "Export",
        dashboard_title: "Security Dashboard",
        dashboard_subtitle: "Real-time endpoint monitoring and threat detection",
        active_threats: "Active Threats",
        monitored_processes: "Monitored Processes",
        network_connections: "Network Connections",
        risk_score: "Avg Risk Score",
        processes_running: "processes running",
        baseline_status: "Above baseline",
        threat_distribution: "Threat Distribution",
        recent_activity: "Recent Activity",
        view_all: "View All",
        no_activity: "No recent security events",
        system_resources: "System Resources",
        latest_alerts: "Latest Alerts",
        no_alerts: "No active alerts",
        processes_title: "Process Monitor",
        processes_subtitle: "Active processes and behavioral analysis",
        search_placeholder: "Search processes...",
        filter_all: "All Processes",
        filter_anomaly: "Anomalies Only",
        filter_high_cpu: "High CPU",
        filter_network: "Network Active",
        col_pid: "PID",
        col_name: "Name",
        col_user: "User",
        col_cpu: "CPU %",
        col_memory: "Memory",
        col_connections: "Connections",
        col_status: "Status",
        col_risk: "Risk",
        loading: "Loading...",
        network_title: "Network Monitor",
        network_subtitle: "Active connections and network activity",
        active_connections: "Active Connections",
        col_local: "Local Address",
        col_remote: "Remote Address",
        col_protocol: "Protocol",
        col_process: "Process",
        events_title: "Security Events",
        events_subtitle: "Detected security incidents and anomalies",
        no_events: "No security events recorded",
        alerts_title: "Alert Center",
        alerts_subtitle: "Security alerts and notifications",
        active_alerts: "Active Alerts",
        ack_all: "Acknowledge All",
        baseline_title: "Baseline Training",
        baseline_subtitle: "Train anomaly detection model on normal system behavior",
        training_duration: "Training Duration",
        start_training: "Start Training",
        simulation_title: "Threat Simulation",
        simulation_subtitle: "Simulate threats for testing detection capabilities",
        simulation_warning_title: "Educational Purpose Only",
        simulation_warning_text: "These simulations generate synthetic threat data for educational and testing purposes. No actual malicious code is executed on your system.",
        sim_ransomware: "Ransomware Behavior",
        sim_ransomware_desc: "Simulates file encryption patterns and ransom note creation",
        sim_backdoor: "Backdoor Connection",
        sim_backdoor_desc: "Simulates C2 communication and encoded commands",
        sim_trojan: "Trojan Injection",
        sim_trojan_desc: "Simulates process injection and malicious DLL loading",
        simulate: "Simulate",
        connected: "Connected",
        disconnected: "Disconnected"
    },
    ar: {
        nav_dashboard: "لوحة التحكم",
        nav_processes: "العمليات",
        nav_network: "الشبكة",
        nav_events: "أحداث الأمان",
        nav_alerts: "التنبيهات",
        section_tools: "الأدوات",
        nav_baseline: "التدريب الأساسي",
        nav_simulation: "محاكاة التهديدات",
        refresh: "تحديث",
        export: "تصدير",
        dashboard_title: "لوحة تحكم الأمان",
        dashboard_subtitle: "مراقبة نقطة النهاية في الوقت الفعلي وكشف التهديدات",
        active_threats: "التهديدات النشطة",
        monitored_processes: "العمليات المراقبة",
        network_connections: "اتصالات الشبكة",
        risk_score: "متوسط درجة المخاطرة",
        processes_running: "عمليات قيد التشغيل",
        baseline_status: "فوق الخط الأساسي",
        threat_distribution: "توزيع التهديدات",
        recent_activity: "النشاط الأخير",
        view_all: "عرض الكل",
        no_activity: "لا توجد أحداث أمان حديثة",
        system_resources: "موارد النظام",
        latest_alerts: "أحدث التنبيهات",
        no_alerts: "لا توجد تنبيهات نشطة",
        processes_title: "مراقبة العمليات",
        processes_subtitle: "العمليات النشطة والتحليل السلوكي",
        search_placeholder: "البحث في العمليات...",
        filter_all: "جميع العمليات",
        filter_anomaly: "الحالات الشاذة فقط",
        filter_high_cpu: "استهلاك عالٍ للمعالج",
        filter_network: "نشط على الشبكة",
        col_pid: "المعرف",
        col_name: "الاسم",
        col_user: "المستخدم",
        col_cpu: "المعالج %",
        col_memory: "الذاكرة",
        col_connections: "الاتصالات",
        col_status: "الحالة",
        col_risk: "المخاطرة",
        loading: "جاري التحميل...",
        network_title: "مراقبة الشبكة",
        network_subtitle: "الاتصالات النشطة ونشاط الشبكة",
        active_connections: "الاتصالات النشطة",
        col_local: "العنوان المحلي",
        col_remote: "العنوان البعيد",
        col_protocol: "البروتوكول",
        col_process: "العملية",
        events_title: "أحداث الأمان",
        events_subtitle: "الحوادث الأمنية المكتشفة والحالات الشاذة",
        no_events: "لا توجد أحداث أمان مسجلة",
        alerts_title: "مركز التنبيهات",
        alerts_subtitle: "تنبيهات الأمان والإشعارات",
        active_alerts: "التنبيهات النشطة",
        ack_all: "إقرار الكل",
        baseline_title: "التدريب الأساسي",
        baseline_subtitle: "تدريب نموذج الكشف على السلوك الطبيعي للنظام",
        training_duration: "مدة التدريب",
        start_training: "بدء التدريب",
        simulation_title: "محاكاة التهديدات",
        simulation_subtitle: "محاكاة التهديدات لاختبار قدرات الكشف",
        simulation_warning_title: "لأغراض تعليمية فقط",
        simulation_warning_text: "تقوم هذه المحاكاات بإنشاء بيانات تهديدات تركيبية لأغراض تعليمية واختبارية. لا يتم تنفيذ أي تعليمات برمجية ضارة فعلية على نظامك.",
        sim_ransomware: "سلوك الفدية",
        sim_ransomware_desc: "محاكاة أنماط تشفير الملفات وإنشاء رسالة الفدية",
        sim_backdoor: "اتصال الباب الخلفي",
        sim_backdoor_desc: "محاكاة الاتصال بمركز التحكم والأوامر المشفرة",
        sim_trojan: "حقن حصان طروادة",
        sim_trojan_desc: "محاكاة حقن العملية وتحميل المكتبات الضارة",
        simulate: "محاكاة",
        connected: "متصل",
        disconnected: "غير متصل"
    },
    ko: {
        nav_dashboard: "대시보드",
        nav_processes: "프로세스",
        nav_network: "네트워크",
        nav_events: "보안 이벤트",
        nav_alerts: "알림",
        section_tools: "도구",
        nav_baseline: "베이스라인 학습",
        nav_simulation: "위협 시뮬레이션",
        refresh: "새로고침",
        export: "보내기",
        dashboard_title: "보안 대시보드",
        dashboard_subtitle: "실시간 엔드포인트 모니터링 및 위협 감지",
        active_threats: "활성 위협",
        monitored_processes: "모니터링 중인 프로세스",
        network_connections: "네트워크 연결",
        risk_score: "평균 위험 점수",
        processes_running: "실행 중인 프로세스",
        baseline_status: "베이스라인 이상",
        threat_distribution: "위협 분포",
        recent_activity: "최근 활동",
        view_all: "모두 보기",
        no_activity: "최근 보안 이벤트 없음",
        system_resources: "시스템 리소스",
        latest_alerts: "최신 알림",
        no_alerts: "활성 알림 없음",
        processes_title: "프로세스 모니터",
        processes_subtitle: "활성 프로세스 및 행동 분석",
        search_placeholder: "프로세스 검색...",
        filter_all: "모든 프로세스",
        filter_anomaly: "이상 징후만",
        filter_high_cpu: "높은 CPU 사용",
        filter_network: "네트워크 활성",
        col_pid: "PID",
        col_name: "이름",
        col_user: "사용자",
        col_cpu: "CPU %",
        col_memory: "메모리",
        col_connections: "연결",
        col_status: "상태",
        col_risk: "위험",
        loading: "로딩 중...",
        network_title: "네트워크 모니터",
        network_subtitle: "활성 연결 및 네트워크 활동",
        active_connections: "활성 연결",
        col_local: "로컬 주소",
        col_remote: "원격 주소",
        col_protocol: "프로토콜",
        col_process: "프로세스",
        events_title: "보안 이벤트",
        events_subtitle: "감지된 보안 사고 및 이상 징후",
        no_events: "기록된 보안 이벤트 없음",
        alerts_title: "알림 센터",
        alerts_subtitle: "보안 알림 및 알림 메시지",
        active_alerts: "활성 알림",
        ack_all: "모두 확인",
        baseline_title: "베이스라인 학습",
        baseline_subtitle: "정상 시스템 동작에 대한 이상 감지 모델 학습",
        training_duration: "학습 기간",
        start_training: "학습 시작",
        simulation_title: "위협 시뮬레이션",
        simulation_subtitle: "감지 기능 테스트를 위한 위협 시뮬레이션",
        simulation_warning_title: "교육 목적 전용",
        simulation_warning_text: "이 시뮬레이션은 교육 및 테스트 목적을 위해 합성 위협 데이터를 생성합니다. 실제 악성 코드는 시스템에서 실행되지 않습니다.",
        sim_ransomware: "랜섬웨어 동작",
        sim_ransomware_desc: "파일 암호화 패턴과 랜섬 노트 생성 시뮬레이션",
        sim_backdoor: "백도어 연결",
        sim_backdoor_desc: "C2 통신 및 인코딩된 명령 시뮬레이션",
        sim_trojan: "트로이 목마 주입",
        sim_trojan_desc: "프로세스 주입 및 악성 DLL 로딩 시뮬레이션",
        simulate: "시뮬레이션",
        connected: "연결됨",
        disconnected: "연결 끊김"
    }
};

let currentLang = 'en';

function setLanguage(lang) {
    if (!translations[lang]) return;
    
    currentLang = lang;
    
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === 'ar' ? 'rtl' : 'ltr';
    
    document.querySelectorAll('.lang-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.lang === lang);
    });
    
    updatePageTranslations();
}

function updatePageTranslations() {
    const texts = translations[currentLang];
    
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.dataset.i18n;
        if (texts[key]) {
            el.textContent = texts[key];
        }
    });
    
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.dataset.i18nPlaceholder;
        if (texts[key]) {
            el.placeholder = texts[key];
        }
    });
}

function t(key) {
    return translations[currentLang]?.[key] || translations['en']?.[key] || key;
}

document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('.lang-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            setLanguage(btn.dataset.lang);
        });
    });
    
    updatePageTranslations();
});
