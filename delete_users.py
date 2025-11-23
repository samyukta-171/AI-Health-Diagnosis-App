import pymysql

# Database connection
connection = pymysql.connect(
    host='localhost',
    user='root',
    password='_samyukta_',
    database='healthcare_db',
    cursorclass=pymysql.cursors.DictCursor
)

try:
    with connection.cursor() as cursor:
        # Find users by their mobile numbers
        mobile_numbers = ['9597325924', '7200848405']
        
        # Get user IDs first
        cursor.execute("SELECT id, username FROM user WHERE role='patient'")
        all_users = cursor.fetchall()
        
        print("Current users in database:")
        for user in all_users:
            print(f"  ID: {user['id']}, Username: {user['username']}")
        
        # Find the patient IDs associated with these mobile numbers
        cursor.execute("SELECT id, first_name, last_name, mobile FROM patient WHERE mobile IN (%s, %s)", mobile_numbers)
        patients = cursor.fetchall()
        
        if not patients:
            print("\nNo patients found with those mobile numbers.")
        else:
            print(f"\nFound {len(patients)} patients to delete:")
            for patient in patients:
                print(f"  {patient['first_name']} {patient['last_name']} - Mobile: {patient['mobile']}")
            
            # Ask for confirmation
            confirm = input("\nDo you want to delete these users? (yes/no): ")
            
            if confirm.lower() == 'yes':
                for patient in patients:
                    patient_id = patient['id']
                    
                    # Delete all related records first
                    cursor.execute("DELETE FROM diagnosis_record WHERE patient_id = %s", (patient_id,))
                    print(f"  Deleted diagnosis records for patient {patient_id}")
                    
                    cursor.execute("DELETE FROM lab_report_record WHERE patient_id = %s", (patient_id,))
                    print(f"  Deleted lab report records for patient {patient_id}")
                    
                    cursor.execute("DELETE FROM prescription_record WHERE patient_id = %s", (patient_id,))
                    print(f"  Deleted prescription records for patient {patient_id}")
                    
                    # Get user_id from patient table
                    cursor.execute("SELECT user_id FROM patient WHERE id = %s", (patient_id,))
                    result = cursor.fetchone()
                    user_id = result['user_id']
                    
                    # Delete patient record
                    cursor.execute("DELETE FROM patient WHERE id = %s", (patient_id,))
                    print(f"  Deleted patient record {patient_id}")
                    
                    # Delete user account
                    cursor.execute("DELETE FROM user WHERE id = %s", (user_id,))
                    print(f"  Deleted user account {user_id}")
                
                connection.commit()
                print("\n✅ Users deleted successfully!")
            else:
                print("\nDeletion cancelled.")
    
    # Show remaining users
    with connection.cursor() as cursor:
        cursor.execute("SELECT u.id, u.username, p.first_name, p.last_name, p.mobile FROM user u LEFT JOIN patient p ON u.id = p.user_id WHERE u.role='patient'")
        remaining = cursor.fetchall()
        
        print(f"\nRemaining patients in database: {len(remaining)}")
        for user in remaining:
            if user['first_name']:
                print(f"  {user['first_name']} {user['last_name']} - Mobile: {user['mobile']}")

finally:
    connection.close()
