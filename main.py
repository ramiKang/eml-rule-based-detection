import os
import csv
import sublime

# Configuration
sublime_client = sublime.Sublime()
rules, queries = sublime.util.load_yml_path("./sublime-rules/detection-rules/")

# Process Rule-based Detection
def process_rule_detection(eml_path:str):
    raw_message = sublime.util.load_eml(eml_path)
    response = sublime_client.analyze_message(raw_message, rules, queries)
    matched_rule_list = [item for item in response["rule_results"] if item.get("matched")]

    is_matched = len(matched_rule_list)>0
    matched_rule_name_list = [item["rule"]["name"] for item in matched_rule_list]

    return is_matched, matched_rule_name_list

def main():
    eml_root_path = "./dataset/eml"
    eml_files = [f for f in os.listdir(eml_root_path) if f.lower().endswith(".eml")]

    if not eml_files:
        print("No EML files found in directory.")
        return

    # CSV 결과 저장을 위한 리스트
    results = []

    for eml_file in eml_files:
        eml_path = os.path.join(eml_root_path, eml_file)
        is_matched, matched_rules = process_rule_detection(eml_path)

        # 파일명에서 확장자 제거
        file_name = os.path.splitext(eml_file)[0]
        rules_str = ", ".join(matched_rules) if matched_rules else ""
        
        # 결과를 리스트에 추가
        results.append([file_name, is_matched, rules_str])

        print(f"\n[File] {eml_file} : {is_matched}")
        if matched_rules:
            print("Rules:", "| ".join(matched_rules))
    
    # CSV 파일로 저장
    csv_filename = "email_analysis_results.csv"
    with open(csv_filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['File', 'Phishing', 'Rules'])  # 헤더
        writer.writerows(results)
    
    print(f"\n결과가 {csv_filename}에 저장되었습니다.")

if __name__ == "__main__":
    main()
