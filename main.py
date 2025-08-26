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
    DEFAULT_CSV_FILENAME = "./dataset/email_analysis_results_one_refactor.csv" # Please change csv path you want

class EmailAnalyzer:
    def __init__(self, rules_path: str = Config.DEFAULT_RULES_PATH,is_execute_sublime:bool=True,is_execute_virustotal:bool=True):
        try:
            # Setup parameter
            self.is_execute_virustotal = is_execute_virustotal
            self.is_execute_sublime = is_execute_sublime

            # Sublime Configuration
            if self.is_execute_sublime:
                self.sublime_client = sublime.Sublime()
                self.rules, self.queries = sublime.util.load_yml_path(rules_path)

            # Virus Total Configuration
            if self.is_execute_virustotal:
                self.total_virus_client = vt.Client(os.getenv("TOTAL_VIRUS_API_KEY"))

        except Exception as e:
            print(f"Error initializing EmailAnalyzer: {e}")
            sys.exit(1)
    
    def process_rule_detection(self, eml_path: str) -> Tuple[bool, List[str]]:
        try:
            # 1. Validate eml file
            self.__validate_eml_path__(eml_path)

            # 2. Check Malicious Flag using Sublime
            raw_message = sublime.util.load_eml(eml_path)
            response = self.sublime_client.analyze_message(raw_message, self.rules, self.queries)

            # 3. Post-Processing of sublime's response
            # 3-1. Check if the rule_results attribute exist in the response
            if "rule_results" not in response:
                print(f"Warning: No rule_results in response for {eml_path}")
                return False, []

            # 3-2. Extract rules matched by the rule-based detection
            matched_rule_list = [item for item in response["rule_results"] if item.get("matched")]

            # 3-3. Convert the return format
            is_malicious = len(matched_rule_list) > 0
            matched_rule_name_list = [item["rule"]["name"] for item in matched_rule_list]
            
            return is_malicious, matched_rule_name_list

        except Exception as e:
            print(f"Sublime Error processing {eml_path}: {e}")
            return False, []

    def process_total_virus_detection(self,eml_path)->Tuple[bool, List[str]]:
        try:
            # 1. Validate eml file
            self.__validate_eml_path__(eml_path)

            # 2. Check Malicious Flag using Sublime
            with open(eml_path,"rb") as f:
                analysis = self.total_virus_client.scan_file(f, wait_for_completion=True)

            self.total_virus_client.close()

            # 3. Post-Processing of total virus's analysis
            # 3-1. Check if the results attribute exist in the analysis
            if not hasattr(analysis, 'results'):
                print(f"Warning: No results attribute in analysis for {eml_path}")
                return False, []

            # 3-2. Extract rules matched by the rule-based detection
            malicious_result_list = [item for item in analysis.results.values() if item.get("category") == "malicious"]

            # 3-3. Convert the return formath
            is_malicious = len(malicious_result_list) > 0
            malicious_engine_result_list = [item["result"] for item in malicious_result_list]

            return is_malicious, malicious_engine_result_list

        except Exception as e:
            print(f"Total Virus Error processing {eml_path}: {e}")
            return False, 0

    def save_results_to_csv(self, results: List, filename: str = Config.DEFAULT_CSV_FILENAME) -> None:
        try:
            # 1. Mapping header and attributes
            header_mapping = {
                "filename": "filename",
                "Sublime Result": "flag_sublime",
                "Sublime Detail": "detail_sublime",
                "Virustotal Result": "flag_virustotal",
                "Virustotal Detail": "detail_virustotal",
            }

            # 2. Setup csv hader
            csv_header = ["filename"]

            if self.is_execute_sublime:
                csv_header.extend(["Sublime Result", "Sublime Detail"])
            if self.is_execute_virustotal:
                csv_header.extend(["Virustotal Result", "Virustotal Detail"])

            # 3. Write CSV
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(csv_header)

                # 결과 dict에서 header_mapping 기준으로 값 추출
                for result in results:
                    row = [result.get(header_mapping[col], "") for col in csv_header]
                    writer.writerow(row)

            print(f"\n결과가 {filename}에 저장되었습니다.")

        except Exception as e:
            print(f"Error saving CSV: {e}")
    
    def analyze_directory(self,eml_root_path: str = Config.DEFAULT_EML_ROOT_PATH,
                         csv_filename: str = Config.DEFAULT_CSV_FILENAME) -> None:
        try:
            # 1. Extract eml's list
            # 1.1. Check if a directory exists
            root_path = Path(eml_root_path)

            if not root_path.exists():
                print(f"Directory not found: {eml_root_path}")
                return

            # 1.2. Check if eml's file list
            eml_files = [f for f in os.listdir(eml_root_path) if f.lower().endswith(".eml")]
            
            if not eml_files:
                print("No EML files found in directory.")
                return

            # 2. Execute phishing detection
            print(f"Analyzing {len(eml_files)} EML files...")

            results = []

            for idx, eml_file in enumerate(eml_files, 1):
                detection_result = {}

                percentage = (idx / len(eml_files)) * 100
                progress_line = f"\n[File {idx}/{len(eml_files)} ({percentage:.1f}%)] {eml_file} : "

                # 2.1. Setup eml's path
                eml_path = os.path.join(eml_root_path, eml_file)
                eml_file_name = os.path.splitext(eml_file)[0]

                detection_result["filename"] = eml_file_name

                # 2.2. Execute detection tools
                if self.is_execute_sublime:
                    is_malicious_sublime, matched_rules = self.process_rule_detection(eml_path)
                    sublime_detail_str = self.__parse_detail_result_list__(matched_rules)

                    detection_result["flag_sublime"] = is_malicious_sublime
                    detection_result["detail_sublime"] = sublime_detail_str

                    progress_line += f"Sublime : {is_malicious_sublime} -> {sublime_detail_str} \n"

                if self.is_execute_virustotal:
                    is_malicious_virustotal, malicious_engine_result_list = self.process_total_virus_detection(eml_path)
                    virustotal_detail_str = self.__parse_detail_result_list__(malicious_engine_result_list)

                    detection_result["flag_virustotal"] = is_malicious_virustotal
                    detection_result["detail_virustotal"] = virustotal_detail_str

                    progress_line += f"Virustotal : {is_malicious_virustotal} -> {virustotal_detail_str}"

                # 3. Append result in array
                results.append(detection_result)

                # 4. Show progress indicator
                print(progress_line)

            # Close Session
            if self.is_execute_virustotal:
                self.total_virus_client.close()

            # 3. Check result
            total_files = len(results)

            print(f"\n=== 분석 완료 ===")
            print(f"총 파일 수: {total_files}")

            if self.is_execute_sublime:
                malicious_cnt_sublime = sum(1 for result in results if result["flag_sublime"])
                benign_cnt_sublime = total_files - malicious_cnt_sublime

                print(f"Sublime - malicious: {malicious_cnt_sublime} / benign: {benign_cnt_sublime}")

            if self.is_execute_virustotal:
                malicious_cnt_virustotal = sum(1 for result in results if result["flag_virustotal"])
                benign_cnt_virustotal= total_files - malicious_cnt_virustotal

                print(f"Virustotal - malicious: {malicious_cnt_virustotal} / benign: {benign_cnt_virustotal}")

            # 4, Save CSV
            self.save_results_to_csv(results, csv_filename)
                    
        except Exception as e:
            print(f"Error analyzing directory: {e}")

    def __validate_eml_path__(self, eml_path):
        if not Path(eml_path).exists():
            raise FileNotFoundError(f"EML file not found: {eml_path}")
        
        if not eml_path.lower().endswith('.eml'):
            raise ValueError(f"File must be an EML file: {eml_path}")

    def __parse_detail_result_list__(self,result_list):
        parse_str = " | ".join(result_list) if result_list else ""
        return parse_str


def main():
    load_dotenv()

    """Main function to run email analysis."""
    analyzer = EmailAnalyzer(is_execute_virustotal=False)
    analyzer.analyze_directory()

if __name__ == "__main__":
    main()
