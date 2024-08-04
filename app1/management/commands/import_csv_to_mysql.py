# myapp/management/commands/import_csv_to_mysql.py

import csv
from django.core.management.base import BaseCommand, CommandError
from app1.models import Record_java  # Import your model

class Command(BaseCommand):
    help = 'Import CSV data into MySQL'

    def add_arguments(self, parser):
        parser.add_argument('csv_file', type=str, help='Path to the CSV file')

    def handle(self, *args, **kwargs):
        csv_file = kwargs['csv_file']

        try:
            with open(csv_file, 'r') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    record = Record_java(
                        name=row['name'],
                        education=row['education'],
                        passed_out_year=row['passed_out_year'],
                        college=row['college'],
                        occupation=row['occupation'],
                        company_name=row['company_name'],
                        phone=row['phone'],
                        email=row['email'],
                        father_name=row['father_name'],
                        father_occupation=row['father_occupation'],
                        mother_name=row['mother_name'],
                        mother_occupation=row['mother_occupation'],
                        address=row['address'],
                        city=row['city'],
                        state=row['state'],
                        zipcode=row['zipcode'],
                        country=row['country'],
                        batch_number=row['batch_number'],
                        disclaimer=row['disclaimer'],

                    )
                    record.save()

            self.stdout.write(self.style.SUCCESS('Successfully imported data from CSV to MySQL'))
        except FileNotFoundError:
            raise CommandError(f'File "{csv_file}" does not exist')

