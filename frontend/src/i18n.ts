import type { TabId } from "./types";

export type Lang = "th" | "en";

export const NAV_LABELS: Record<Lang, Record<TabId, string>> = {
  th: {
    overview: "ภาพรวม (Overview)",
    scanner: "สแกนอุปกรณ์ (Scanner)",
    topology: "แผนผังเครือข่าย",
    ipam: "IPAM & NetFlow",
    ids: "IDS, Incidents & SOAR",
    forensics: "วิเคราะห์หลักฐาน & A4",
    tools: "เครื่องมือช่าง & Monitor",
    snmp: "SNMP & LLDP",
    firewall: "Firewall & Policy",
    enterprise: "องค์กร & โรงพยาบาล",
    lab: "ศูนย์ฝึก Blue Team",
  },
  en: {
    overview: "Overview",
    scanner: "IP Scanner",
    topology: "Topology Map",
    ipam: "IPAM & NetFlow",
    ids: "IDS, Incidents & SOAR",
    forensics: "Forensics & Reports",
    tools: "Tools & Monitors",
    snmp: "SNMP & Traffic",
    firewall: "Firewall & Policy",
    enterprise: "Enterprise & Hospital",
    lab: "Blue Team Lab",
  },
};

export const EASY_NAV_LABELS: Record<Lang, Partial<Record<TabId, string>>> = {
  th: {
    overview: "หน้าหลัก (ตรวจสุขภาพ 1 คลิก)",
    scanner: "อุปกรณ์ที่เกาะ Wi-Fi",
    firewall: "แจ้งเตือน & บล็อกภัยคุกคาม",
  },
  en: {
    overview: "Home (1-Click Check)",
    scanner: "Wi-Fi Devices",
    firewall: "Alerts & Block",
  },
};

const DICT: Record<Lang, Record<string, string>> = {
  th: {
    search_shortcut: "ค้นหาด่วน (Ctrl+K)",
    easy_mode: "โหมดใช้งานง่าย",
    pro_mode: "โหมดผู้เชี่ยวชาญ",
    live_stream: "สตรีมสด",
    reconnecting: "กำลังเชื่อมต่อใหม่",
    print_report: "พิมพ์รายงาน A4",
  },
  en: {
    search_shortcut: "Quick Search (Ctrl+K)",
    easy_mode: "Easy Mode",
    pro_mode: "Pro SOC Mode",
    live_stream: "Live Stream",
    reconnecting: "Reconnecting",
    print_report: "Print A4 Report",
  },
};

export function t(lang: Lang, key: string): string {
  return DICT[lang][key] ?? key;
}
