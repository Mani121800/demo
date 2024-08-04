# myapp/management/commands/export_mysql_to_csv.py

import csv
from django.core.management.base import BaseCommand
from app1.models import Record  # Import your model

class Command(BaseCommand):
    help = 'Export MySQL data to CSV'

    def handle(self, *args, **kwargs):
        queryset = Record.objects.all()  # Fetch all records from your model
        filename = 'mysql_data.csv'

        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['name', 'education', 'passed_out_year', 'college', 'occupation', 'company_name', 'phone', 'email', 'father_name', 'father_occupation', 'mother_name', 'mother_occupation', 'address', 'city', 'state', 'zipcode', 'country', 'batch_number', 'disclaimer', 'cert']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for record in queryset:
                writer.writerow({
                    'name': record.name,
                    'education': record.education,
                    'passed_out_year': record.passed_out_year,
                    'college': record.college,
                    'occupation': record.occupation,
                    'company_name': record.company_name,
                    'phone': record.phone,
                    'email': record.email,
                    'father_name': record.father_name,
                    'father_occupation': record.father_occupation,
                    'mother_name': record.mother_name,
                    'mother_occupation': record.mother_occupation,
                    'address': record.address,
                    'city': record.city,
                    'state': record.state,
                    'zipcode': record.zipcode,
                    'country': record.country,
                    'batch_number': record.batch_number,
                    'disclaimer': record.disclaimer,
                    'cert': record.cert,
                })

        self.stdout.write(self.style.SUCCESS(f'Successfully exported MySQL data to {filename}'))
