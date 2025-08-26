import os
import csv
import sys
from pathlib import Path
from typing import List, Tuple
import sublime
import vt
from dotenv import load_dotenv

class Config:
    DEFAULT_RULES_PATH = "./sublime-rules/detection-rules/" # Don't change this path
    DEFAULT_EML_ROOT_PATH = "./dataset/test_one" # Please change your raw eml file path
    DEFAULT_CSV_FILENAME = "./dataset/email_analysis_results_one.csv" # Please change csv path you want

class EmailAnalyzer:
    def __init__(self, rules_path: str = Config.DEFAULT_RULES_PATH):
        try:
            self.total_virus_client = vt.Client(os.getenv("TOTAL_VIRUS_API_KEY"))
            self.sublime_client = sublime.Sublime()
            self.rules, self.queries = sublime.util.load_yml_path(rules_path)
        except Exception as e:
            print(f"Error initializing EmailAnalyzer: {e}")
            sys.exit(1)
    
    def process_rule_detection(self, eml_path: str) -> Tuple[bool, List[str]]:
        try:
            if not Path(eml_path).exists():
                raise FileNotFoundError(f"EML file not found: {eml_path}")
                
            raw_message = sublime.util.load_eml(eml_path)
            response = self.sublime_client.analyze_message(raw_message, self.rules, self.queries)
            
            if "rule_results" not in response:
                print(f"Warning: No rule_results in response for {eml_path}")
                return False, []
                
            matched_rule_list = [item for item in response["rule_results"] if item.get("matched")]
            is_matched = len(matched_rule_list) > 0
            matched_rule_name_list = [item["rule"]["name"] for item in matched_rule_list]
            
            return is_matched, matched_rule_name_list
            
        except Exception as e:
            print(f"Sublime Error processing {eml_path}: {e}")
            return False, []

    def process_total_virus_detection(self,eml_path)->Tuple[bool, List[str]]:
        try:
            with open(eml_path,"rb") as f:
                analysis = self.total_virus_client.scan_file(f, wait_for_completion=True)

            malicious_count = analysis.stats.data["malicious"]

            is_matched = malicious_count > 0

            return is_matched, malicious_count
        except Exception as e:
            print(f"Total Virus Error processing {eml_path}: {e}")
            return False, 0

    def save_results_to_csv(self, results: List[List], filename: str = Config.DEFAULT_CSV_FILENAME) -> None:
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['File', 'Phishing', 'Rules',"Phishing Total Virus","Total Virus Count"])  # Header
                writer.writerows(results)
            print(f"\n결과가 {filename}에 저장되었습니다.")
        except Exception as e:
            print(f"Error saving CSV: {e}")
    
    def analyze_directory(self, eml_root_path: str = Config.DEFAULT_EML_ROOT_PATH, 
                         csv_filename: str = Config.DEFAULT_CSV_FILENAME) -> None:
        try:
            root_path = Path(eml_root_path)
            if not root_path.exists():
                print(f"Directory not found: {eml_root_path}")
                return
                
            eml_files = [f for f in os.listdir(eml_root_path) if f.lower().endswith(".eml")]
            
            if not eml_files:
                print("No EML files found in directory.")
                return
                
            print(f"Analyzing {len(eml_files)} EML files...")
            results = []

            for idx, eml_file in enumerate(eml_files, 1):
                eml_path = os.path.join(eml_root_path, eml_file)
                is_matched, matched_rules = self.process_rule_detection(eml_path)
                is_matched_total_virus, matched_count = self.process_total_virus_detection(eml_path)

                # 파일명에서 확장자 제거
                file_name = os.path.splitext(eml_file)[0]
                rules_str = " | ".join(matched_rules) if matched_rules else ""
                
                # 결과를 리스트에 추가
                results.append([file_name, is_matched, rules_str,is_matched_total_virus, matched_count])
                
                # 진행 상황과 퍼센트 표시
                percentage = (idx / len(eml_files)) * 100
                print(f"\n[File {idx}/{len(eml_files)} ({percentage:.1f}%)] {eml_file} : {is_matched} {is_matched_total_virus} {matched_count}")
                if matched_rules:
                    print("Rules:", ", ".join(matched_rules))

            self.total_virus_client.close()

            # 결과 요약 출력
            total_files = len(results)
            matched_files = sum(1 for result in results if result[1])
            total_virus_matched_files = sum(1 for result in results if result[3])

            unmatched_files = total_files - matched_files
            total_virus_unmatched_files = total_files - total_virus_matched_files

            print(f"\n=== 분석 완료 ===")
            print(f"총 파일 수: {total_files}")
            print(f"매칭된 파일: {matched_files}")
            print(f"매칭되지 않은 파일: {unmatched_files}")
            print(f"Total Virus: {total_virus_matched_files}")
            print(f"Not Total Virus: {total_virus_unmatched_files}")

            # CSV 파일로 저장
            self.save_results_to_csv(results, csv_filename)
                    
        except Exception as e:
            print(f"Error analyzing directory: {e}")


def main():
    load_dotenv()

    """Main function to run email analysis."""
    analyzer = EmailAnalyzer()
    analyzer.analyze_directory()

if __name__ == "__main__":
    main()
