import os
import csv
import sys
from pathlib import Path
from typing import List, Tuple
import sublime

# Constants
class Config:
    DEFAULT_RULES_PATH = "./sublime-rules/detection-rules/" # Don't change this path
    DEFAULT_EML_ROOT_PATH = "./dataset/eml" # Please change your raw eml file path
    DEFAULT_CSV_FILENAME = "./dataset/email_analysis_results.csv" # Please change csv path you want

class EmailAnalyzer:
    def __init__(self, rules_path: str = Config.DEFAULT_RULES_PATH):
        try:
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
            print(f"Error processing {eml_path}: {e}")
            return False, []

    def save_results_to_csv(self, results: List[List], filename: str = Config.DEFAULT_CSV_FILENAME) -> None:
        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['File', 'Phishing', 'Rules'])  # Header
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

            for eml_file in eml_files:
                eml_path = os.path.join(eml_root_path, eml_file)
                is_matched, matched_rules = self.process_rule_detection(eml_path)

                # 파일명에서 확장자 제거
                file_name = os.path.splitext(eml_file)[0]
                rules_str = " | ".join(matched_rules) if matched_rules else ""
                
                # 결과를 리스트에 추가
                results.append([file_name, is_matched, rules_str])

                print(f"\n[File] {eml_file} : {is_matched}")
                if matched_rules:
                    print("Rules:", ", ".join(matched_rules))
            
            # CSV 파일로 저장
            self.save_results_to_csv(results, csv_filename)
                    
        except Exception as e:
            print(f"Error analyzing directory: {e}")


def main():
    """Main function to run email analysis."""
    analyzer = EmailAnalyzer()
    analyzer.analyze_directory()

if __name__ == "__main__":
    main()
