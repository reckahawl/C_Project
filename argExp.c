#include<stdio.h>
#include<argp.h>
const char *argp_program_version = "argex 1.0";
const char *argp_program_bug_address = "<bug-gnu-utils@gnu.org>";
// Structure is used by main to communicate with parse_opt

struct arguments{
    char *args[2]; // ARG1 and ARG2
    int verbose;   // The -v flag
    char *outfile; // argument for -o
    char *string1, *string2; //argument for -a and -b
};

/*
 *OPTIONS. Field 1 in ARGP
 *Order of fields: {NAME, KEY, ARG, FLAGS, DOC}
 */

static struct arg_option options[] = {
    {"verbose", 'v', 0, 0, "Produce verbose output"},
    {"alpha", 'a', "STRING1", 0,"Do something with STRING1 related to the letter A"},
    {"bravo", 'b', "STRING2",0,"Do something with STRING2 to related to letter B"},
    {"output", 'o', "OUTFILE",0,"Output to OUTFILE instead of standard output"},
    {0}
};

/*
 *PARSER. Field 2 in ARGP
 *Order of parameters: KEY, ARG, STATE
 */

static error_t parse_opt(int key, char *arg, struct argp_state *state){
    struct arguments *arguments = state->input;
    switch(key){
        case 'v':
            arguments->verbose = 1;
            break;
        case 'a':
            arguments->string1 = arg;
            break;
        case 'b':
            arguments->string2 = arg;
            break;
        case 'o':
            arguments->outfile=arg;
            break;
        case ARGP_KEY_ARG:
            if(state->arg_num >= 2){
                argp_usage(state);
            };
            arguments->args[state->arg_num] = arg;
            break;
        case ARGP_KEY_END:
            if(state->arg_num < 2){
                argp_usage(state);
            };
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

/*
 *ARG_DOC. Field 3 ARGP.
 *A description of the non-option command-line arguments tha we accept.
 */

static char args_doc[] = "ARG! ARG2";

/*
 *DOC. Field 4 in ARGP.
 *Program documentation.
 */

static char doc[]="argex -- A pragram to domonstrate how to code command line options ang arguments.\vFrom the GNU C.";
// The ARGP structure itself.

static struct argp argp = {options, parse_opt, arg_doc, doc};


int main(int argc, char **argv[]){
    struct arguments arguments;
    FILE *outstream;
    char waters[]="A FIFO special file is similar to a pipe, but instead of being an anonymous, temporary
connection, a FIFO has a name or names like any other file. Processes open the FIFO by
name in order to communicate through it.
A pipe or FIFO has to be open at both ends simultaneously. If you read from a pipe or
FIFO file that doesn’t have any processes writing to it (perhaps because they have all closed
the file, or exited), the read returns end-of-file. Writing to a pipe or FIFO that doesn’t have
a reading process is treated as an error condition; it generates a SIGPIPE signal, and fails
with error code EPIPE if the signal is handled or blocked
--\"the gunners dream\", Rodger Waters, 1999\n";
    arguments.outfile = NULL;
    arguments.string1 = "";
    arguments.string2 = "";
    arguments.verbose = 0;

    argp_parse(&argp, argc, agrv,0,0, &arguments);

    if(arguments.outfile) outstream = fopen(arguments.outfile, "w");
    else outstream = stdout;

    fprintf(outstream, "alpha = %s\nbravo = %s\n\n", arguments.string1, arguments.string2);
    fprintf(outstream, "ARG1 = %s\nARG2 = %s\n\n", arguments.args[0],arguments.args[1]);

    if(arguments.verbose) fprintf(outstream, waters);

    return 0;
}
