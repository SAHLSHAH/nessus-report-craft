
import React, { useState } from 'react';
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import * as z from "zod";
import { format } from "date-fns";

import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Calendar as CalendarIcon, Upload } from "lucide-react";
import { cn } from "@/lib/utils";

const formSchema = z.object({
  companyName: z.string().min(1, { message: "Company name is required" }),
  reportDate: z.date({ required_error: "Report date is required" }),
  preparedBy: z.string().min(1, { message: "Preparer name is required" }),
  companyLogo: z.any().optional(),
});

export type CompanyDetails = z.infer<typeof formSchema>;

interface CompanyDetailsFormProps {
  onSubmit: (data: CompanyDetails) => void;
  isDisabled?: boolean;
}

const CompanyDetailsForm: React.FC<CompanyDetailsFormProps> = ({ 
  onSubmit,
  isDisabled = false
}) => {
  const [logoPreview, setLogoPreview] = useState<string | null>(null);

  const form = useForm<CompanyDetails>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      companyName: "",
      reportDate: new Date(),
      preparedBy: "",
    },
  });

  const handleLogoChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      const reader = new FileReader();
      reader.onloadend = () => {
        setLogoPreview(reader.result as string);
        form.setValue('companyLogo', reader.result);
      };
      reader.readAsDataURL(file);
    }
  };

  const handleSubmit = (values: CompanyDetails) => {
    onSubmit({ ...values, companyLogo: logoPreview });
  };

  return (
    <Form {...form}>
      <form onSubmit={form.handleSubmit(handleSubmit)} className="space-y-6">
        <div className="grid gap-6 md:grid-cols-2">
          <FormField
            control={form.control}
            name="companyName"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Company Name</FormLabel>
                <FormControl>
                  <Input placeholder="Acme Corporation" {...field} disabled={isDisabled} />
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="reportDate"
            render={({ field }) => (
              <FormItem className="flex flex-col">
                <FormLabel>Report Date</FormLabel>
                <Popover>
                  <PopoverTrigger asChild>
                    <FormControl>
                      <Button
                        variant={"outline"}
                        className={cn(
                          "w-full pl-3 text-left font-normal",
                          !field.value && "text-muted-foreground"
                        )}
                        disabled={isDisabled}
                      >
                        {field.value ? (
                          format(field.value, "PPP")
                        ) : (
                          <span>Pick a date</span>
                        )}
                        <CalendarIcon className="ml-auto h-4 w-4 opacity-50" />
                      </Button>
                    </FormControl>
                  </PopoverTrigger>
                  <PopoverContent className="w-auto p-0" align="start">
                    <Calendar
                      mode="single"
                      selected={field.value}
                      onSelect={field.onChange}
                      disabled={(date) => 
                        date > new Date() || date < new Date("2000-01-01")
                      }
                      initialFocus
                    />
                  </PopoverContent>
                </Popover>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="preparedBy"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Prepared By</FormLabel>
              <FormControl>
                <Input placeholder="John Doe" {...field} disabled={isDisabled} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="companyLogo"
          render={() => (
            <FormItem>
              <FormLabel>Company Logo</FormLabel>
              <FormControl>
                <div className="flex flex-col items-center space-y-4">
                  {logoPreview && (
                    <div className="w-32 h-32 border rounded-lg overflow-hidden">
                      <img 
                        src={logoPreview} 
                        alt="Company logo preview" 
                        className="w-full h-full object-contain"
                      />
                    </div>
                  )}
                  <Input
                    type="file"
                    accept="image/*"
                    onChange={handleLogoChange}
                    disabled={isDisabled}
                    className="w-full"
                  />
                </div>
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />

        <Button 
          type="submit" 
          className="w-full"
          disabled={isDisabled}
        >
          Generate Report
        </Button>
      </form>
    </Form>
  );
};

export default CompanyDetailsForm;
